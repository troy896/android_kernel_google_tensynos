#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/xattr.h>
#include <linux/uaccess.h>
#include "nomount.h"

static struct kmem_cache *nm_dir_cachep __read_mostly, *nm_inode_cachep __read_mostly;
static const struct cred *nm_root_cred;
static DEFINE_STATIC_KEY_FALSE(nomount_active_uids);

/*** Helpers ***/

static __always_inline bool nomount_is_uid_blocked(uid_t uid) 
{
    bool is_blocked;
    if (!static_branch_unlikely(&nomount_active_uids)) return false;
    rcu_read_lock();
    is_blocked = (idr_find(&nomount_uid_idr, uid) != NULL);
    rcu_read_unlock();
    return is_blocked;
}

#define __get_nm(ptr, type, member) ({ \
    u64 __sig = 0; \
    type *__o = likely(ptr) ? container_of(ptr, type, member) : NULL; \
    (__o && nm_probe_read(&__sig, &__o->signature, sizeof(__sig)) == 0 && __sig == NOMOUNT_MAGIC_SIG) ? __o : NULL; \
})

static __always_inline struct nomount_dir_node *nomount_get_dir_node(struct inode *inode) 
{
    struct nm_iop *nm_iop;
    struct nm_fop *nm_fop;

    nm_iop = __get_nm(smp_load_acquire(&inode->i_op), struct nm_iop, fake_iop);
    if (nm_iop && nm_iop->dir_node) return nm_iop->dir_node;

    nm_fop = __get_nm(smp_load_acquire(&inode->i_fop), struct nm_fop, fake_fop);
    if (nm_fop && nm_fop->dir_node) return nm_fop->dir_node;
    
    return NULL;
}

static __always_inline struct nomount_rule *nomount_find_child_rule(struct nomount_dir_node *dir_node, const char *name, size_t len, u32 hash)
{
    struct nomount_child_node *child;
    struct nomount_rule *found = NULL;
    int id;

    rcu_read_lock();
    idr_for_each_entry(&dir_node->children_idr, child, id) {
        if (child->name_hash == hash && child->name_len == len && memcmp(child->name, name, len) == 0) {
            found = child->rule;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}

struct nomount_proxy_ctx {
    struct dir_context ctx;
    struct dir_context *orig_ctx;
    struct nomount_dir_node *dir_node;
};

static NM_ACTOR_RET nomount_actor_proxy(struct dir_context *ctx, const char *name, int namelen,
                                        loff_t offset, u64 ino, unsigned int d_type)
{
    struct nomount_proxy_ctx *proxy = container_of(ctx, struct nomount_proxy_ctx, ctx);
    struct nomount_child_node *child;
    NM_ACTOR_RET ret;
    u32 hash;
    int id;

    if (!proxy->dir_node) return NM_ACTOR_CONTINUE;
    hash = full_name_hash(NULL, name, namelen);
    if (!(proxy->dir_node->bloom_mask & (1ULL << (hash & 63))))
        goto do_real_actor;

    rcu_read_lock();
    idr_for_each_entry(&proxy->dir_node->children_idr, child, id) {
        if (child->name_hash == hash && child->name_len == namelen && memcmp(child->name, name, namelen) == 0) {
            rcu_read_unlock();
            proxy->ctx.pos = offset;
            return NM_ACTOR_CONTINUE;
        }
    }
    rcu_read_unlock();

do_real_actor:
    proxy->orig_ctx->pos = proxy->ctx.pos;
    ret = proxy->orig_ctx->actor(proxy->orig_ctx, name, namelen, offset, ino, d_type);
    proxy->ctx.pos = proxy->orig_ctx->pos;

    return ret;
}

static inline void nomount_emit_virtual_children(struct dir_context *ctx, struct nomount_dir_node *dir_node)
{
    struct nomount_child_node *child;
    int id;

    if (!dir_node) return;
    if (!nm_is_virtual_pos(ctx->pos)) ctx->pos = nm_pack_pos(0);
    id = nm_unpack_pos(ctx->pos);

    rcu_read_lock();
    idr_for_each_entry_continue(&dir_node->children_idr, child, id) {
        ctx->pos = nm_pack_pos(id);
        if (!(child->flags & NM_FLAG_WHITEOUT) && !(child->flags & NM_FLAG_HIDDEN)) {
            if (!dir_emit(ctx, child->name, child->name_len, child->fake_ino, child->d_type))
                break;
        }
        ctx->pos = nm_pack_pos(id + 1);
    }
    rcu_read_unlock();
}

/*** file / inode / superblock operations ***/

static int nm_open(struct inode *inode, struct file *file)
{
    struct nm_inode_info *info = inode->i_private;
    struct file *real_file;
    const struct cred *old_cred;

    if (unlikely(!info)) return -ENODEV;
    if (info->flags & (NM_FLAG_INTERNAL_DIR | NM_FLAG_INTERNAL_API)) {
        file->private_data = NULL;
        return 0;
    }
    if (unlikely(!info->r_path.dentry)) return -ENODEV;

    old_cred = override_creds(nm_root_cred);
    real_file = dentry_open(&info->r_path, file->f_flags, nm_root_cred);
    revert_creds(old_cred);
    if (IS_ERR(real_file)) return PTR_ERR(real_file);

    file->private_data = real_file;
    return 0;
}

static int nm_release(struct inode *inode, struct file *file)
{
    struct file *real_file = file->private_data;
    if (real_file) {
        fput(real_file);
        file->private_data = NULL;
    }
    return 0;
}

static loff_t nm_llseek(struct file *file, loff_t offset, int whence)
{
    struct file *real_file = file->private_data;
    loff_t res;
    if (!real_file) return -EINVAL;

    real_file->f_pos = file->f_pos;
    res = vfs_llseek(real_file, offset, whence);
    file->f_pos = real_file->f_pos;

    return res;
}

static ssize_t nm_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
    struct file *file = iocb->ki_filp;
    struct file *real_file = file->private_data;
    ssize_t ret;
    if (!real_file || !real_file->f_op->read_iter) return -EINVAL;

    iocb->ki_filp = real_file;
    ret = real_file->f_op->read_iter(iocb, to);
    iocb->ki_filp = file;

    return ret;
}

static ssize_t nm_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    struct file *file = iocb->ki_filp;
    struct file *real_file = file->private_data;
    ssize_t ret;
    if (!real_file || !real_file->f_op->write_iter) return -EINVAL;

    iocb->ki_filp = real_file;
    ret = real_file->f_op->write_iter(iocb, from);
    iocb->ki_filp = file;

    return ret;
}

static int nm_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct file *real_file = file->private_data;
    int ret;
    if (!real_file || !real_file->f_op->mmap) return -ENODEV;

    vma->vm_file = real_file;
    ret = real_file->f_op->mmap(real_file, vma);
    vma->vm_file = file;

    return ret;
}

static long nm_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct file *real_file = file->private_data;
    if (!real_file || !real_file->f_op->unlocked_ioctl) return -ENOTTY;
    return real_file->f_op->unlocked_ioctl(real_file, cmd, arg);
}

#ifdef CONFIG_COMPAT
static long nm_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct file *real_file = file->private_data;
    if (!real_file || !real_file->f_op->compat_ioctl) return -ENOTTY;
    return real_file->f_op->compat_ioctl(real_file, cmd, arg);
}
#endif

static ssize_t nm_splice_read(struct file *in, loff_t *ppos, struct pipe_inode_info *pipe,
                              size_t len, unsigned int flags)
{
    struct file *real_file = in->private_data;
    if (!real_file || !real_file->f_op->splice_read) return -EINVAL;
    return real_file->f_op->splice_read(real_file, ppos, pipe, len, flags);
}

static ssize_t nm_splice_write(struct pipe_inode_info *pipe, struct file *out,
                               loff_t *ppos, size_t len, unsigned int flags)
{
    struct file *real_file = out->private_data;
    if (!real_file || !real_file->f_op->splice_write) return -EINVAL;
    return real_file->f_op->splice_write(pipe, real_file, ppos, len, flags);
}

static int nm_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct file *real_file = file->private_data;
    if (!real_file || !real_file->f_op->fsync) return -EINVAL;
    return real_file->f_op->fsync(real_file, start, end, datasync);
}

static const struct file_operations nm_fops = {
    .owner = THIS_MODULE,
    .llseek = nm_llseek,
    .open = nm_open,
    .release = nm_release,
    .read_iter = nm_read_iter,
    .write_iter = nm_write_iter,
    .mmap = nm_mmap,
    .unlocked_ioctl = nm_unlocked_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = nm_compat_ioctl,
#endif
    .splice_read = nm_splice_read,
    .splice_write = nm_splice_write,
    .fsync = nm_fsync,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
static int nm_mmap_prepare(struct vm_area_desc *desc)
{
    struct file *file = desc->file;
    struct file *real_file = file->private_data;
    int ret;
    if (!real_file || !real_file->f_op->mmap_prepare) return -ENODEV;

    desc->file = real_file;
    ret = real_file->f_op->mmap_prepare(desc);
    desc->file = file;

    return ret;
}

static const struct file_operations nm_fops_mmap_prepare = {
    .owner = THIS_MODULE,
    .llseek = nm_llseek,
    .open = nm_open,
    .release = nm_release,
    .read_iter = nm_read_iter,
    .write_iter = nm_write_iter,
    .mmap_prepare = nm_mmap_prepare,
    .unlocked_ioctl = nm_unlocked_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = nm_compat_ioctl,
#endif
    .splice_read = nm_splice_read,
    .splice_write = nm_splice_write,
    .fsync = nm_fsync,
};
#endif

static ssize_t nm_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
    struct nm_inode_info *info = d_backing_inode(dentry)->i_private;
    if (unlikely(!info || (info->flags & NM_FLAG_HIDDEN))) return -ENOENT;
    if (unlikely((info->flags & NM_FLAG_INTERNAL_DIR) || !d_backing_inode(info->r_path.dentry)->i_op->listxattr))
        return -EOPNOTSUPP;

    return d_backing_inode(info->r_path.dentry)->i_op->listxattr(info->r_path.dentry, buffer, size);
}

static int nm_file_getattr(IDMAP_ARG const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
    struct inode *v_inode = d_backing_inode(path->dentry);
    struct nm_inode_info *info = v_inode->i_private;
    int res;
    if (unlikely(!info)) return -EIO;
    if (unlikely(info->flags & NM_FLAG_HIDDEN)) return -ENOENT;

    if (unlikely(info->flags & NM_FLAG_INTERNAL_DIR)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
        generic_fillattr(IDMAP_CALL request_mask, v_inode, stat);
#else
        generic_fillattr(IDMAP_CALL v_inode, stat);
#endif
        stat->ino = info->v_ino;
        stat->dev = v_inode->i_sb->s_dev;
        return 0;
    }

    res = vfs_getattr_nosec(&info->r_path, stat, request_mask, query_flags);
    if (likely(res == 0)) {
        if (likely(info->flags & NM_FLAG_HAS_STAT)) {
            stat->size = info->v_size;
            stat->blocks = info->v_blocks;
        }
        stat->ino = info->v_ino;
        stat->dev = v_inode->i_sb->s_dev;
    }
    return res;
}

static int nm_setattr(IDMAP_ARG struct dentry *dentry, struct iattr *attr)
{
    struct inode *v_inode = d_inode(dentry);
    struct nm_inode_info *info = v_inode->i_private;
    int err;

    if (unlikely(!info)) return -EIO;
    if (unlikely(info->flags & NM_FLAG_HIDDEN)) return -ENOENT;
    if (info->flags & NM_FLAG_INTERNAL_DIR) return 0;

    inode_lock(d_backing_inode(info->r_path.dentry));
    err = notify_change(IDMAP_CALL info->r_path.dentry, attr, NULL);
    inode_unlock(d_backing_inode(info->r_path.dentry));

    if (likely(!err)) {
        if (attr->ia_valid & ATTR_MODE) v_inode->i_mode = d_backing_inode(info->r_path.dentry)->i_mode;
        if (attr->ia_valid & ATTR_UID)  v_inode->i_uid = d_backing_inode(info->r_path.dentry)->i_uid;
        if (attr->ia_valid & ATTR_GID)  v_inode->i_gid = d_backing_inode(info->r_path.dentry)->i_gid;
        nm_sync_inode_times(v_inode, d_backing_inode(info->r_path.dentry));
    }
    return err;
}

static const char *nm_get_link(struct dentry *dentry, struct inode *inode, struct delayed_call *done)
{
    struct nm_inode_info *info = inode->i_private;
    struct inode *real_inode;
    struct dentry *target_dentry;
    if (unlikely(!info || !info->r_path.dentry)) return ERR_PTR(-ECHILD);

    real_inode = d_backing_inode(info->r_path.dentry);
    target_dentry = dentry ? info->r_path.dentry : NULL;
    if (real_inode && real_inode->i_op && real_inode->i_op->get_link) {
        return real_inode->i_op->get_link(target_dentry, real_inode, done);
    }

    return ERR_PTR(-EINVAL);
}

static int nm_api_permission(IDMAP_ARG struct inode *inode, int mask)
{
    if (current_uid().val != 0 || mask & (MAY_ACCESS | MAY_EXEC)) return -ENOENT;
    return 0;
}

static const struct inode_operations nm_api_iops = {
    .permission = nm_api_permission,
    .getattr = nm_file_getattr,
    .setattr = nm_setattr,
};

static const struct inode_operations nm_file_iops = {
    .getattr = nm_file_getattr,
    .setattr = nm_setattr,
    .listxattr = nm_listxattr,
};

static const struct inode_operations nm_symlink_iops = {
    .getattr = simple_getattr,
    .setattr = nm_setattr,
    .get_link = nm_get_link,
    .listxattr = nm_listxattr,
};

static int nm_dir_iterate_dir(struct file *file, struct dir_context *ctx)
{
    struct nm_inode_info *info = file_inode(file)->i_private;
    struct nomount_dir_node *dir_node = info ? info->dir_node : NULL;
    struct file *real_file = file->private_data;
    int res = 0;

    if (!nm_is_virtual_pos(ctx->pos) && ctx->pos != 0x7FFFFFFFFFFFFFFFLL) {
        if (real_file && real_file->f_op->iterate_shared) {
            loff_t old_pos = ctx->pos;
            struct nomount_proxy_ctx proxy_ctx = {
                .ctx.actor = nomount_actor_proxy, .ctx.pos = ctx->pos,
                .orig_ctx = ctx, .dir_node = dir_node
            };
            res = nm_call_iterate(real_file, &proxy_ctx.ctx, real_file->f_op);
            ctx->pos = proxy_ctx.ctx.pos;
            if (ctx->pos != old_pos || res < 0) return res;
            ctx->pos = nm_pack_pos(0);
        } else if (info && (info->flags & NM_FLAG_INTERNAL_DIR)) {
            if (!dir_emit_dots(file, ctx)) return 0;
            ctx->pos = nm_pack_pos(0);
        } else return -ENOTDIR;
    }

    if (res >= 0) nomount_emit_virtual_children(ctx, dir_node);
    return res;
}

// Forward declaration
static struct inode *nomount_create_new_inode(struct super_block *virtual_sb,
                                              struct nomount_rule *rule);
static struct dentry *nm_dir_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    struct inode *r_dir = nm_get_real_inode(dir);
    struct nm_inode_info *info = dir->i_private;
    const char *name = dentry->d_name.name;
    size_t len = dentry->d_name.len;

    if (info && info->dir_node) {
        u32 v_hash = full_name_hash(NULL, name, len);
        struct nomount_rule *c_rule = nomount_find_child_rule(info->dir_node, name, len, v_hash);
        if (c_rule) {
            if (c_rule->flags & NM_FLAG_WHITEOUT) { d_add(dentry, NULL); return NULL; }
            if ((c_rule->flags & (NM_FLAG_INTERNAL_DIR | NM_FLAG_INTERNAL_API)) || c_rule->r_path.dentry) {
                struct inode *new_inode = nomount_create_new_inode(dir->i_sb, c_rule);
                if (new_inode) return d_splice_alias(new_inode, dentry);
            }
        }
    }

    if (r_dir && r_dir->i_op && r_dir->i_op->lookup)
        return r_dir->i_op->lookup(r_dir, dentry, flags);

    if (info && (info->flags & NM_FLAG_INTERNAL_DIR)) {
        d_add(dentry, NULL);
        return NULL;
    }
    return ERR_PTR(-EOPNOTSUPP);
}

static const struct file_operations nm_dir_fops = {
    .owner = THIS_MODULE,
    .open = nm_open,
    .release = nm_release,
    .llseek = nm_llseek,
    .read = generic_read_dir,
    .iterate_shared = nm_dir_iterate_dir,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
    .iterate = nm_dir_iterate_dir,
#endif
};

static const struct inode_operations nm_dir_iops = {
    .lookup = nm_dir_lookup,
    .getattr = nm_file_getattr,
    .setattr = nm_setattr,
    .listxattr = nm_listxattr,
};

struct nm_xattr_proxy {
    struct xattr_handler fake;
    const struct xattr_handler *orig;
};

static int nm_xattr_get(const struct xattr_handler *handler, struct dentry *dentry, struct inode *inode, const char *name, void *buffer, size_t size FLAGS_ARG)
{
    struct nm_xattr_proxy *proxy = container_of(handler, struct nm_xattr_proxy, fake);
    if (inode->i_op == &nm_file_iops || inode->i_op == &nm_symlink_iops || inode->i_op == &nm_dir_iops) {
        struct nm_inode_info *info = inode->i_private;
        if (unlikely(!info || !info->r_path.dentry)) return -ENODATA;
        return vfs_getxattr(IDMAP_PATH(info->r_path) info->r_path.dentry, name, buffer, size);
    }
    return proxy->orig->get(proxy->orig, dentry, inode, name, buffer, size FLAGS_VAL);
}

static int nm_xattr_set(const struct xattr_handler *handler, IDMAP_ARG struct dentry *dentry, struct inode *inode, const char *name, const void *buffer, size_t size, int flags)
{
    struct nm_xattr_proxy *proxy = container_of(handler, struct nm_xattr_proxy, fake);
    if (inode->i_op == &nm_file_iops || inode->i_op == &nm_symlink_iops || inode->i_op == &nm_dir_iops) {
        struct nm_inode_info *info = inode->i_private;
        if (unlikely(!info || !info->r_path.dentry)) return -ENODATA;
        return vfs_setxattr(IDMAP_CALL info->r_path.dentry, name, buffer, size, flags);
    }
    return proxy->orig->set(proxy->orig, IDMAP_CALL dentry, inode, name, buffer, size, flags);
}

/*** i_op / s_op / f_op Hijacking Hooks ***/

// Forward declaration
static const struct file_operations nm_api_fops;
static struct inode *nomount_create_new_inode(struct super_block *virtual_sb, struct nomount_rule *rule)
{
    struct inode *inode;
    struct nm_inode_info *info;

    inode = new_inode(virtual_sb);
    if (unlikely(!inode)) return NULL;

    info = kmem_cache_alloc(nm_inode_cachep, GFP_KERNEL);
    if (unlikely(!info)) {
        iput(inode);
        return NULL;
    }

    info->flags = rule->flags;
    info->dir_node = rule->this_dir;
    if (info->flags & (NM_FLAG_INTERNAL_DIR | NM_FLAG_INTERNAL_API)) {
        info->r_path.dentry = NULL;
        info->r_path.mnt = NULL;
    } else {
        info->r_path = rule->r_path;
        path_get(&info->r_path);
    }

    info->v_ino = rule->v_ino;
    if (rule->flags & NM_FLAG_HAS_STAT) {
        info->v_size = rule->v_size;
        info->v_blocks = rule->v_blocks;
    }

    inode->i_private = info;
    inode->i_ino = rule->v_ino;
    if (rule->flags & NM_FLAG_INTERNAL_API) {
        inode->i_mode = S_IFREG | 0666;
        inode->i_uid = GLOBAL_ROOT_UID;
        inode->i_gid = GLOBAL_ROOT_GID;
        inode->i_op = &nm_api_iops;
        inode->i_fop = &nm_api_fops;
#ifdef IOP_FASTPERM
        inode->i_opflags &= ~IOP_FASTPERM;
#endif
    } else if (rule->flags & NM_FLAG_INTERNAL_DIR) {
        inode->i_mode = S_IFDIR | 0755;
        inode->i_size = 4096;
        inode->i_blocks = 8;
        inode->i_uid = GLOBAL_ROOT_UID;
        inode->i_gid = GLOBAL_ROOT_GID;
        inode->i_op = &nm_dir_iops;
        inode->i_fop = &nm_dir_fops;
    } else {
        struct inode *real_inode = d_backing_inode(rule->r_path.dentry);
        inode->i_mode = real_inode->i_mode;
        inode->i_size = i_size_read(real_inode);
        inode->i_blocks = real_inode->i_blocks;
        inode->i_uid = real_inode->i_uid;
        inode->i_gid = real_inode->i_gid;
        nm_sync_inode_times(inode, real_inode);
        if (S_ISDIR(real_inode->i_mode)) {
            inode->i_op = &nm_dir_iops;
            inode->i_fop = &nm_dir_fops;
        } else if (S_ISLNK(real_inode->i_mode) || (real_inode->i_op && real_inode->i_op->get_link)) {
            inode->i_op = &nm_symlink_iops;
            inode->i_fop = &nm_fops;
        } else { 
            inode->i_op = &nm_file_iops;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
            if (real_inode->i_fop && real_inode->i_fop->mmap_prepare)
                inode->i_fop = &nm_fops_mmap_prepare;
            else
    #endif
                inode->i_fop = &nm_fops;
        }
        inode->i_mapping = real_inode->i_mapping;
    }

    inode->i_flags |= S_PRIVATE | S_NOATIME | S_NOCMTIME | S_NOSEC;
    inode->i_opflags |= IOP_XATTR;
    nm_init_private_list(inode);

    return inode;
}

static struct dentry *nomount_hijacked_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    struct nm_iop *nm_iop = __get_nm(smp_load_acquire(&dir->i_op), struct nm_iop, fake_iop);
    struct nomount_rule *rule;
    const char *name = dentry->d_name.name;
    size_t len = dentry->d_name.len;
    u32 v_hash;

    if (unlikely(nomount_is_uid_blocked(current_uid().val) || !nm_iop || !nm_iop->dir_node))
        goto fallback;

    v_hash = full_name_hash(NULL, name, len);
    rule = nomount_find_child_rule(nm_iop->dir_node, name, len, v_hash);
    if (likely(rule)) {
        if (rule->flags & NM_FLAG_WHITEOUT) {
            d_add(dentry, NULL); 
            return NULL;
        }

        if ((rule->flags & (NM_FLAG_INTERNAL_DIR | NM_FLAG_INTERNAL_API)) || rule->r_path.dentry) {
            struct inode *new_inode = nomount_create_new_inode(dir->i_sb, rule);
            if (likely(new_inode)) {
                if (!(rule->flags & NM_FLAG_INTERNAL_API))
                    nm_debug("Lookup hijacked! Splicing inode %lu into dentry '%s'\n", new_inode->i_ino, name);
                return d_splice_alias(new_inode, dentry);
            }
        }
    }

fallback:
    if (nm_iop && nm_iop->orig_iop && nm_iop->orig_iop->lookup) {
        return nm_iop->orig_iop->lookup(dir, dentry, flags);
    }

    return ERR_PTR(-EOPNOTSUPP);
}

static int nomount_hijacked_iterate_dir(struct file *file, struct dir_context *ctx)
{
    struct nm_fop *nm_fop = __get_nm(smp_load_acquire(&file->f_op), struct nm_fop, fake_fop);
    int res = 0;

    if (unlikely(nomount_is_uid_blocked(current_uid().val) || !nm_fop || !nm_fop->orig_fop || !nm_fop->dir_node))
        goto do_real_iterate;

    if (!nm_is_virtual_pos(ctx->pos) && ctx->pos != 0x7FFFFFFFFFFFFFFFLL) {
        loff_t old_pos = ctx->pos;
        struct nomount_proxy_ctx proxy_ctx = {
            .ctx.actor = nomount_actor_proxy, .ctx.pos = ctx->pos,
            .orig_ctx = ctx, .dir_node = nm_fop->dir_node
        };
        res = nm_call_iterate(file, &proxy_ctx.ctx, nm_fop->orig_fop);
        ctx->pos = proxy_ctx.ctx.pos;
        if (ctx->pos != old_pos || res < 0) return res;
        ctx->pos = nm_pack_pos(0);
    }

    if (res >= 0) nomount_emit_virtual_children(ctx, nm_fop->dir_node);
    return res;

do_real_iterate:
    if (nm_fop && nm_fop->orig_fop) {
        return nm_call_iterate(file, ctx, nm_fop->orig_fop);
    }
    return -ENOTDIR;
}

static int nomount_hijacked_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct inode *inode = d_backing_inode(dentry);
    struct nm_sop *nm_sop;

    if (unlikely(inode && inode->i_op == &nm_api_iops)) return -ENOENT;
    nm_sop = __get_nm(smp_load_acquire(&dentry->d_sb->s_op), struct nm_sop, fake_sop);
    if (nm_sop && nm_sop->orig_sop && nm_sop->orig_sop->statfs)
        return nm_sop->orig_sop->statfs(dentry, buf);

    return -ENOSYS;
}

static void nomount_hijacked_destroy_inode(struct inode *inode)
{
    struct nm_sop *nm_sop;
    if (inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops || inode->i_op == &nm_symlink_iops) {
        if (inode->i_private) {
            struct nm_inode_info *info = inode->i_private;
            if (info->r_path.dentry) {
                path_put(&info->r_path);
            }
            kmem_cache_free(nm_inode_cachep, info);
            inode->i_private = NULL;
        }
    }
    nm_sop = __get_nm(smp_load_acquire(&inode->i_sb->s_op), struct nm_sop, fake_sop);
    if (nm_sop && nm_sop->orig_sop && nm_sop->orig_sop->destroy_inode) {
        nm_sop->orig_sop->destroy_inode(inode);
    }
}

/* --- Hijacking Management --- */

static inline void nomount_hijack_superblock(struct super_block *sb)
{
    struct nm_sop *nm_sop;
    int i, count = 0;
    if (unlikely(!sb || !sb->s_op || __get_nm(smp_load_acquire(&sb->s_op), struct nm_sop, fake_sop))) return;

    nm_sop = kzalloc(sizeof(*nm_sop), GFP_KERNEL);
    if (unlikely(!nm_sop)) return;

    memcpy(&nm_sop->fake_sop, sb->s_op, sizeof(struct super_operations));
    nm_sop->orig_sop = sb->s_op;
    nm_sop->signature = NOMOUNT_MAGIC_SIG;
    nm_sop->sb = sb;
    nm_sop->fake_sop.destroy_inode = nomount_hijacked_destroy_inode;
    if (sb->s_op->statfs) nm_sop->fake_sop.statfs = nomount_hijacked_statfs;

    if (sb->s_xattr && !nm_sop->orig_xattr) {
        const struct xattr_handler **new_array;
        while (sb->s_xattr[count]) count++;
        new_array = kzalloc((count + 1) * sizeof(void *), GFP_KERNEL);
        if (new_array) {
            for (i = 0; i < count; i++) {
                struct nm_xattr_proxy *proxy = kzalloc(sizeof(*proxy), GFP_KERNEL);
                if (!proxy) continue;
                proxy->orig = sb->s_xattr[i];
                proxy->fake.name = proxy->orig->name;
                proxy->fake.prefix = proxy->orig->prefix;
                proxy->fake.flags = proxy->orig->flags;
                proxy->fake.list = proxy->orig->list;
                if (proxy->orig->get) proxy->fake.get = nm_xattr_get;
                if (proxy->orig->set) proxy->fake.set = nm_xattr_set;
                new_array[i] = &proxy->fake;
            }
            nm_sop->orig_xattr = (const struct xattr_handler **)sb->s_xattr;
            nm_sop->fake_xattr = new_array;
            smp_store_release((const struct xattr_handler ***)&sb->s_xattr, new_array);
            nm_debug("xattr handlers successfully hijacked for dev: 0x%x\n", sb->s_dev);
        }
    }

    list_add_tail_rcu(&nm_sop->list, &nomount_sb_list);
    smp_store_release(&sb->s_op, &nm_sop->fake_sop);
    nm_debug("Superblock successfully hijacked for dev: 0x%x\n", sb->s_dev);
}

static inline void nomount_hijack_virtual_parent(struct nomount_dir_node *dir_node, struct inode *inode)
{
    struct nm_fop *nm_fop;
    if (unlikely(!inode->i_fop || __get_nm(smp_load_acquire(&inode->i_fop), struct nm_fop, fake_fop))) return;

    nm_fop = kzalloc(sizeof(*nm_fop), GFP_KERNEL);
    if (likely(nm_fop)) {
        memcpy(&nm_fop->fake_fop, inode->i_fop, sizeof(struct file_operations));
        nm_fop->orig_fop = inode->i_fop;
        nm_fop->signature = NOMOUNT_MAGIC_SIG;
        nm_fop->dir_node = dir_node;

        if (nm_fop->fake_fop.iterate_shared)
            nm_fop->fake_fop.iterate_shared = nomount_hijacked_iterate_dir;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
        else if (nm_fop->fake_fop.iterate)
            nm_fop->fake_fop.iterate = nomount_hijacked_iterate_dir;
#endif

        smp_store_release(&inode->i_fop, &nm_fop->fake_fop);
        nm_debug("i_fop successfully hijacked for virtual parent dir (ino: %lu)\n", inode->i_ino);
    }
}

static inline void nomount_hijack_dir_inode(struct nomount_dir_node *dir_node, struct inode *inode)
{
    struct nm_iop *nm_iop;
    if (unlikely(!inode->i_op || __get_nm(smp_load_acquire(&inode->i_op), struct nm_iop, fake_iop))) return;

    nm_iop = kzalloc(sizeof(*nm_iop), GFP_KERNEL);
    if (likely(nm_iop)) {
        memcpy(&nm_iop->fake_iop, inode->i_op, sizeof(struct inode_operations));
        nm_iop->orig_iop = inode->i_op;
        nm_iop->signature = NOMOUNT_MAGIC_SIG;
        nm_iop->dir_node = dir_node;
        nm_iop->had_private_flag = (inode->i_flags & S_PRIVATE) != 0;

        if (nm_iop->orig_iop->lookup) nm_iop->fake_iop.lookup = nomount_hijacked_lookup;
        smp_store_release(&inode->i_op, &nm_iop->fake_iop);
        inode->i_flags |= S_PRIVATE;
        nm_debug("i_op successfully hijacked for parent dir (ino: %lu)\n", inode->i_ino);
    }
}

static void nomount_invalidate_dcache(const char *v_path)
{
    struct path target_path;
    if (kern_path(v_path, 0, &target_path) == 0) {
        d_drop(target_path.dentry);
        path_put(&target_path);
    }
}

static void nomount_restore_dir_node(struct nomount_dir_node *dir_node)
{
    struct inode *t_inode = dir_node->dir_inode;
    struct nm_iop *nm_iop;
    struct nm_fop *nm_fop;
 
    if (unlikely(!t_inode)) return;

    spin_lock(&t_inode->i_lock);
    nm_iop = __get_nm(smp_load_acquire(&t_inode->i_op), struct nm_iop, fake_iop);
    if (nm_iop && nm_iop->dir_node == dir_node) {
        smp_store_release(&t_inode->i_op, nm_iop->orig_iop);
        if (!nm_iop->had_private_flag) t_inode->i_flags &= ~S_PRIVATE;
        nm_debug("Successfully cured i_op for dir %lu\n", t_inode->i_ino);
        kfree_rcu(nm_iop, rcu);
    }

    nm_fop = __get_nm(smp_load_acquire(&t_inode->i_fop), struct nm_fop, fake_fop);
    if (nm_fop && nm_fop->dir_node == dir_node) {
        smp_store_release(&t_inode->i_fop, nm_fop->orig_fop);
        nm_debug("Successfully cured i_fop for dir %lu\n", t_inode->i_ino);
        kfree_rcu(nm_fop, rcu);
    }
    spin_unlock(&t_inode->i_lock);
    iput(t_inode);
    dir_node->dir_inode = NULL;
}

static void nomount_restore_superblocks(void)
{
    struct nm_sop *nm_sop, *tmp;

    list_for_each_entry_safe(nm_sop, tmp, &nomount_sb_list, list) {
        int i = 0;
        if (nm_sop->sb) {
            smp_store_release(&nm_sop->sb->s_op, nm_sop->orig_sop);
            if (nm_sop->fake_xattr) {
                smp_store_release((const struct xattr_handler ***)&nm_sop->sb->s_xattr, nm_sop->orig_xattr);
                while (nm_sop->orig_xattr[i]) {
                    if (nm_sop->fake_xattr[i]) {
                        kfree(container_of(nm_sop->fake_xattr[i], struct nm_xattr_proxy, fake));
                    }
                    i++;
                }
                kfree(nm_sop->fake_xattr);
            }
            nm_debug("Successfully cured superblock for dev: 0x%x\n", nm_sop->sb->s_dev);
        }
        list_del_rcu(&nm_sop->list);
        kfree_rcu(nm_sop, rcu);
    }
}

/*** Module Management ***/

static struct nomount_dir_node *__nomount_alloc_dir_node(struct inode *inode) 
{
    struct nomount_dir_node *dir_node = kmem_cache_alloc(nm_dir_cachep, GFP_KERNEL);
    if (unlikely(!dir_node)) return NULL;
    dir_node->dir_inode = inode ? igrab(inode) : NULL;
    idr_init(&dir_node->children_idr);
    dir_node->bloom_mask = 0;
    list_add_tail(&dir_node->list, &nomount_all_dirs_list);
    return dir_node;
}

static void __nomount_inject_child_locked(struct nomount_dir_node *dir_node, struct nomount_rule *rule, const char *name, size_t name_len)
{
    struct nomount_child_node *child;
    int id;

    if (unlikely(!dir_node)) return;
    rule->parent_dir = dir_node;
    idr_for_each_entry(&dir_node->children_idr, child, id) {
        if (child->name_len == name_len && memcmp(child->name, name, name_len) == 0) {
            child->flags = rule->flags;
            child->rule = rule;
            return;
        }
    }

    child = kmalloc(sizeof(*child) + name_len + 1, GFP_KERNEL);
    if (unlikely(!child)) return;

    child->fake_ino = rule->v_hash;
    child->name_hash = full_name_hash(NULL, name, name_len);
    child->d_type = (rule->flags & NM_FLAG_IS_DIR) ? DT_DIR : DT_REG;
    child->flags = rule->flags;
    child->name_len = name_len;
    child->rule = rule;
    memcpy(child->name, name, name_len);
    child->name[name_len] = '\0';

    idr_preload(GFP_KERNEL);
    child->id = idr_alloc(&dir_node->children_idr, child, 0, 0, GFP_NOWAIT);
    idr_preload_end();

    if (child->id < 0) {
        kfree(child);
        return;
    }

    dir_node->bloom_mask |= (1ULL << (child->name_hash & 63));
}

static void __nomount_delete_child_locked(struct nomount_dir_node *dir_node, unsigned long fake_ino, struct list_head *d_victims)
{
    struct nomount_child_node *child;
    int id;

    if (unlikely(!dir_node)) return;
    idr_for_each_entry(&dir_node->children_idr, child, id) {
        if (child->fake_ino == fake_ino) {
            idr_remove(&dir_node->children_idr, id);
            kfree_rcu(child, rcu);
            break;
        }
    }
    if (idr_is_empty(&dir_node->children_idr)) {
        list_del(&dir_node->list);
        list_add(&dir_node->list, d_victims);
    } else {
        dir_node->bloom_mask = 0;
        idr_for_each_entry(&dir_node->children_idr, child, id) {
            dir_node->bloom_mask |= (1ULL << (child->name_hash & 63));
        }
    }
}

static int nomount_generate_virtual_topology(struct nomount_rule *target_rule)
{
    struct nomount_rule *irule, *ex, *current_rule = target_rule;
    char orig_v_path, *v_path = nm_get_vpath(target_rule);
    int parent_len, p_len = target_rule->v_len;
    const char *child_name, *lookup_path;
    struct nomount_dir_node *dir_node;
    struct hlist_node *tmp;
    struct inode *v_inode;
    struct dentry *dentry;
    struct path p_path;
    struct qstr qname;
    bool found_virtual;
    size_t child_len, irule_size;
    int i, err = 0;
    u32 h_parent;
    HLIST_HEAD(pending_list);

    while (p_len > 1) {
        for (i = p_len - 1; i >= 0; i--) {
            if (v_path[i] == '/') break;
        }

        parent_len = (i == 0) ? 1 : i;
        child_name = v_path + i + 1;
        child_len = p_len - i - 1;
        h_parent = full_name_hash(NULL, v_path, parent_len);
        orig_v_path = v_path[i];
        if (i > 0) v_path[i] = '\0';

        found_virtual = false;
        hash_for_each_possible(nomount_rules_ht, ex, vpath_node, h_parent) {
            if (ex->v_len == parent_len && memcmp(nm_get_vpath(ex), v_path, parent_len) == 0) {
                dir_node = ex->this_dir;
                if (!dir_node) {
                    dir_node = __nomount_alloc_dir_node(NULL);
                    ex->this_dir = dir_node;
                }
                __nomount_inject_child_locked(dir_node, current_rule, child_name, child_len);
                found_virtual = true;
                break;
            }
        }

        if (found_virtual) {
            if (i > 0) v_path[i] = orig_v_path; 
            break;
        }

        lookup_path = (parent_len == 1) ? "/" : v_path;
        if (kern_path(lookup_path, LOOKUP_FOLLOW, &p_path) == 0) {
            v_inode = d_backing_inode(p_path.dentry);
            dir_node = nomount_get_dir_node(v_inode);
            if (!dir_node) dir_node = __nomount_alloc_dir_node(v_inode);
            if (likely(dir_node)) {
                nomount_hijack_virtual_parent(dir_node, v_inode);
                nomount_hijack_dir_inode(dir_node, v_inode);
                nomount_hijack_superblock(p_path.dentry->d_sb);

                qname.name = child_name;
                qname.len = child_len;
                qname.hash = full_name_hash(p_path.dentry, child_name, child_len);
                if (p_path.dentry->d_flags & DCACHE_OP_HASH)
                    p_path.dentry->d_op->d_hash(p_path.dentry, &qname);

                dentry = d_lookup(p_path.dentry, &qname);
                if (dentry) {
                    d_drop(dentry); 
                    dput(dentry);
                }
                __nomount_inject_child_locked(dir_node, current_rule, child_name, child_len);
            }
            path_put(&p_path);
            
            if (i > 0) v_path[i] = orig_v_path; 
            break;
        }

        irule_size = sizeof(struct nomount_rule) + parent_len + 1 + 2; 
        irule = kzalloc(irule_size, GFP_KERNEL);
        if (!irule) {
            err = -ENOMEM;
            if (i > 0) v_path[i] = orig_v_path; 
            break;
        }

        irule->v_len = parent_len;
        irule->v_hash = h_parent;
        irule->flags = NM_FLAG_IS_DIR | NM_FLAG_INTERNAL_DIR;
        irule->v_ino = (unsigned long)h_parent;

        memcpy(nm_get_vpath(irule), v_path, parent_len);
        nm_get_vpath(irule)[parent_len] = '\0';
        nm_get_rpath(irule)[0] = '\0';

        dir_node = __nomount_alloc_dir_node(NULL);
        irule->this_dir = dir_node;
        __nomount_inject_child_locked(dir_node, current_rule, child_name, child_len);
        hlist_add_head(&irule->vpath_node, &pending_list);
        current_rule = irule;
        if (i > 0) v_path[i] = orig_v_path;
        p_len = i; 
    }

    if (likely(err == 0)) {
        hlist_for_each_entry_safe(irule, tmp, &pending_list, vpath_node) {
            hlist_del_init(&irule->vpath_node); 
            hash_add_rcu(nomount_rules_ht, &irule->vpath_node, irule->v_hash);
        }
    } else {
        hlist_for_each_entry_safe(irule, tmp, &pending_list, vpath_node) {
            hlist_del_init(&irule->vpath_node);
            if (irule->r_path.dentry) path_put(&irule->r_path);
            if (irule->this_dir) {
                struct nomount_child_node *child; int id;
                idr_for_each_entry(&irule->this_dir->children_idr, child, id) {
                    kfree(child);
                }
                idr_destroy(&irule->this_dir->children_idr);
                list_del(&irule->this_dir->list);
                kmem_cache_free(nm_dir_cachep, irule->this_dir); 
            }
            kfree(irule);
        }
    }

    return err;
}

/*** Rule Operations ***/

static int __nomount_add_rule(const char *v_path, const char *r_path, u16 v_len, u16 r_len, u32 flags)
{
    struct nomount_rule *rule = NULL, *existing, *victim = NULL;
    bool is_whiteout = (flags & NM_FLAG_WHITEOUT);
    bool is_api = (flags & NM_FLAG_INTERNAL_API);
    struct path v_path_struct;
    int err = 0;

    if (!v_path || (!r_path && !is_whiteout && !is_api)) return -EINVAL;
    while (v_len > 1 && v_path[v_len - 1] == '/') { v_len--; }
    if (!is_whiteout && !is_api) { while (r_len > 1 && r_path[r_len - 1] == '/') { r_len--; } }

    if (is_whiteout || is_api) r_len = 0;
    rule = kzalloc((sizeof(struct nomount_rule) + v_len + 1 + r_len + 1), GFP_KERNEL);
    if (!rule) return -ENOMEM;

    INIT_HLIST_NODE(&rule->vpath_node);
    rule->v_hash = full_name_hash(NULL, v_path, v_len);
    rule->flags = flags;
    rule->v_len = v_len;
    memcpy(nm_get_vpath(rule), v_path, v_len);
    nm_get_vpath(rule)[v_len] = '\0';

    if (is_whiteout || is_api) {
        nm_get_rpath(rule)[0] = '\0';
    } else {
        memcpy(nm_get_rpath(rule), r_path, r_len);
        nm_get_rpath(rule)[r_len] = '\0';
    }

    if (!is_whiteout && !is_api && kern_path(nm_get_rpath(rule), LOOKUP_FOLLOW, &rule->r_path) ==  0 &&
         S_ISDIR(d_backing_inode(rule->r_path.dentry)->i_mode)) rule->flags |= NM_FLAG_IS_DIR;

    if (kern_path(nm_get_vpath(rule), LOOKUP_FOLLOW, &v_path_struct) == 0) {
        struct kstat temp_stat;
        rule->v_ino = d_backing_inode(v_path_struct.dentry)->i_ino;
        vfs_getattr(&v_path_struct, &temp_stat, (STATX_BASIC_STATS | STATX_BTIME), AT_STATX_SYNC_AS_STAT);

        rule->flags |= NM_FLAG_HAS_STAT;
        rule->v_size = temp_stat.size;
        rule->v_blocks = temp_stat.blocks;
        path_put(&v_path_struct);
    } else {
         rule->v_ino = (unsigned long)rule->v_hash;
    }

    mutex_lock(&nomount_write_mutex);
    hash_for_each_possible(nomount_rules_ht, existing, vpath_node, rule->v_hash) {
        if (existing->v_hash == rule->v_hash && existing->v_len == v_len &&
             memcmp(nm_get_vpath(existing), nm_get_vpath(rule), v_len) == 0) {
            hash_del_rcu(&existing->vpath_node);
            victim = existing;
            nm_info("Shadowing existing rule for: %s\n", nm_get_vpath(rule));
            break;
        }
    }

    err = nomount_generate_virtual_topology(rule);
    if (err != 0) {
        mutex_unlock(&nomount_write_mutex);
        if (rule->r_path.dentry) path_put(&rule->r_path);
        kfree(rule); 
        return err;
    }

    hash_add_rcu(nomount_rules_ht, &rule->vpath_node, rule->v_hash);
    mutex_unlock(&nomount_write_mutex);

    if (unlikely(victim)) {
        synchronize_rcu();
        if (victim->r_path.dentry) path_put(&victim->r_path);
        kfree(victim);
    }

    if (is_whiteout)
        nm_info("Successfully added whiteout rule: %s\n", nm_get_vpath(rule));
    else if (is_api)
        nm_info("Successfully registered Internal API: %s\n", nm_get_vpath(rule));
    else
        nm_info("Successfully added injection rule: %s -> %s\n", nm_get_vpath(rule), nm_get_rpath(rule));
        
    return 0;
}

static void __nomount_del_rule(const char *v_path, size_t v_len, struct hlist_head *r_victims, struct list_head *d_victims)
{
    struct nomount_rule *rule;
    u32 hash = full_name_hash(NULL, v_path, v_len);

    hash_for_each_possible(nomount_rules_ht, rule, vpath_node, hash) {
        if (rule->v_hash == hash && rule->v_len == v_len &&
                memcmp(nm_get_vpath(rule), v_path, v_len) == 0) {
            nomount_invalidate_dcache(v_path);
            hash_del_rcu(&rule->vpath_node);
            hlist_add_head(&rule->vpath_node, r_victims);
            if (rule->parent_dir)
                __nomount_delete_child_locked(rule->parent_dir, hash, d_victims);
            break;
        }
    }
}

static void __nomount_clear_all(void)
{
    struct nomount_rule *rule;
    struct nomount_dir_node *dir_node, *tmp_dir;
    struct nomount_child_node *child;
    struct hlist_node *hlist_tmp;
    HLIST_HEAD(rule_victims);
    LIST_HEAD(dir_victims);
    LIST_HEAD(uid_victims);
    int bkt, id;

    hash_for_each_safe(nomount_rules_ht, bkt, hlist_tmp, rule, vpath_node) {
        nomount_invalidate_dcache(nm_get_vpath(rule));
        hash_del_rcu(&rule->vpath_node);
        hlist_add_head(&rule->vpath_node, &rule_victims);
    }

    list_for_each_entry_safe(dir_node, tmp_dir, &nomount_all_dirs_list, list) {
        list_del(&dir_node->list);
        idr_for_each_entry(&dir_node->children_idr, child, id) {
            kfree_rcu(child, rcu);
        }
        idr_destroy(&dir_node->children_idr);
        list_add_tail(&dir_node->list, &dir_victims);
    }

    static_branch_disable(&nomount_active_uids);
    idr_destroy(&nomount_uid_idr);
    INIT_LIST_HEAD(&nomount_all_dirs_list);
    synchronize_rcu();

    hlist_for_each_entry_safe(rule, hlist_tmp, &rule_victims, vpath_node) {
        if (rule->r_path.dentry) path_put(&rule->r_path);
        kfree(rule);
    }
    list_for_each_entry_safe(dir_node, tmp_dir, &dir_victims, list) {
        nomount_restore_dir_node(dir_node);
        kmem_cache_free(nm_dir_cachep, dir_node);
    }

    nomount_restore_superblocks();
}

/*** Internal API ioctl Endpoint ***/

static long nm_api_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct nm_api_payload *payload;
    struct hlist_node *tmp;
    HLIST_HEAD(r_victims);
    LIST_HEAD(d_victims);
    const char *v_ptr, *r_ptr;
    long ret = 0;

    if (current_uid().val != 0) return -ENOENT;
    payload = kmalloc(sizeof(struct nm_api_payload), GFP_KERNEL);
    if (!payload) return -ENOMEM;

    if (_IOC_DIR(cmd) & _IOC_WRITE) {
        if (copy_from_user(payload, (void __user *)arg, sizeof(*payload))) {
            ret = -EFAULT;
            goto out;
        }
        if (payload->magic_sig != NOMOUNT_MAGIC_SIG) {
            ret = -ENOTTY;
            goto out;
        }
    }

    switch (cmd) {
        case NM_IOC_ADD_RULE:
            if (payload->v_len >= PATH_MAX || payload->r_len >= PATH_MAX) { ret = -EINVAL; break; }
            payload->paths[sizeof(payload->paths) - 1] = '\0';
            v_ptr = payload->paths;
            r_ptr = payload->paths + payload->v_len + 1;
            ret = __nomount_add_rule(v_ptr, r_ptr, payload->v_len, payload->r_len, payload->flags);
            break;

        case NM_IOC_DEL_RULE:
            if (payload->v_len >= PATH_MAX) { ret = -EINVAL; break; }
            payload->paths[sizeof(payload->paths) - 1] = '\0';
            v_ptr = payload->paths;

            mutex_lock(&nomount_write_mutex);
            __nomount_del_rule(v_ptr, payload->v_len, &r_victims, &d_victims);
            mutex_unlock(&nomount_write_mutex);

            if (hlist_empty(&r_victims)) { ret = -ENOENT; break; }
            synchronize_rcu();

            {
                struct nomount_rule *rule;
                struct nomount_dir_node *dir_node, *tmp_dir;
                hlist_for_each_entry_safe(rule, tmp, &r_victims, vpath_node) {
                    nm_info("Deleted rule for: %s\n", nm_get_vpath(rule));
                    if (rule->r_path.dentry) path_put(&rule->r_path);
                    kfree(rule);
                }
                list_for_each_entry_safe(dir_node, tmp_dir, &d_victims, list) {
                    nomount_restore_dir_node(dir_node);
                    kmem_cache_free(nm_dir_cachep, dir_node);
                }
            }
            break;

        case NM_IOC_CLEAR_ALL:
            mutex_lock(&nomount_write_mutex);
            __nomount_clear_all();
            mutex_unlock(&nomount_write_mutex);
            nm_info("Cleared all active rules and UIDs\n");
            break;

        case NM_IOC_ADD_UID:
            if (nomount_is_uid_blocked(payload->uid)) { ret = -EEXIST; break; }
            mutex_lock(&nomount_write_mutex);
            idr_preload(GFP_KERNEL);
            ret = idr_alloc(&nomount_uid_idr, (void *)1, payload->uid, payload->uid + 1, GFP_NOWAIT);
            idr_preload_end();

            if (ret >= 0) {
                static_branch_enable(&nomount_active_uids);
                ret = 0;
                nm_info("Successfully added blocked UID: %u\n", payload->uid);
            } else {
                ret = -ENOMEM;
            }
            mutex_unlock(&nomount_write_mutex);
            break;

        case NM_IOC_DEL_UID:
            mutex_lock(&nomount_write_mutex);
            if (idr_remove(&nomount_uid_idr, payload->uid)) {
                if (idr_is_empty(&nomount_uid_idr)) static_branch_disable(&nomount_active_uids);
                nm_info("Successfully removed blocked UID: %u\n", payload->uid);
            } else {
                ret = -ENOENT;
            }
            mutex_unlock(&nomount_write_mutex);
            break;

        case NM_IOC_GET_VER:
            payload->version = NOMOUNT_VERSION;
            if (copy_to_user((void __user *)arg, payload, sizeof(*payload)))
                ret = -EFAULT;
            break;

        case NM_IOC_GET_RULE:
            {
                struct nomount_rule *rule;
                int bkt, target_idx = payload->flags;
                int valid_idx = 0;
                bool found = false;
                rcu_read_lock();
                hash_for_each_rcu(nomount_rules_ht, bkt, rule, vpath_node) {
                    if (rule->flags & NM_FLAG_INTERNAL_API) continue;
                    if (valid_idx == target_idx) {
                        payload->v_len = rule->v_len;
                        payload->r_len = (rule->flags & NM_FLAG_WHITEOUT) ? 0 : strlen(nm_get_rpath(rule));
                        payload->flags = rule->flags;
                        memcpy(payload->paths, nm_get_vpath(rule), payload->v_len + 1);
                        if (!(rule->flags & NM_FLAG_WHITEOUT))
                            memcpy(payload->paths + payload->v_len + 1, nm_get_rpath(rule), payload->r_len + 1);
                        found = true;
                        break;
                    }
                    valid_idx++;
                }
                rcu_read_unlock();
                if (!found) { ret = -ENOENT; break; }
                if (copy_to_user((void __user *)arg, payload, sizeof(*payload)))
                    ret = -EFAULT;
            }
            break;

        default:
            ret = -ENOTTY;
            break;
    }

out:
    kfree(payload);
    return ret;
}

static const struct file_operations nm_api_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = nm_api_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = nm_api_ioctl,
#endif
};

static int __init nomount_init(void)
{
    int ret;

    struct cred *cred = prepare_creds();
    if (!cred) { return -ENOMEM; }
    cred->uid = cred->euid = cred->suid = cred->fsuid = GLOBAL_ROOT_UID;
    cred->gid = cred->egid = cred->sgid = cred->fsgid = GLOBAL_ROOT_GID;
    cap_raise(cred->cap_effective, CAP_DAC_OVERRIDE);
    cap_raise(cred->cap_effective, CAP_DAC_READ_SEARCH);
    nm_root_cred = cred;

    hash_init(nomount_rules_ht);
    nm_dir_cachep = kmem_cache_create("nm_dirs", sizeof(struct nomount_dir_node), 0, SLAB_HWCACHE_ALIGN, NULL);
    nm_inode_cachep = kmem_cache_create("nm_inodes", sizeof(struct nm_inode_info), 0, SLAB_HWCACHE_ALIGN, NULL);

    if (!nm_dir_cachep || !nm_inode_cachep) {
        nm_err("Failed to allocate memory slab caches\n");
        if (nm_dir_cachep) kmem_cache_destroy(nm_dir_cachep);
        if (nm_inode_cachep) kmem_cache_destroy(nm_inode_cachep);
        put_cred(nm_root_cred);
        return -ENOMEM;
    }

    ret = __nomount_add_rule("/dev/nomount", NULL, 12, 0, NM_FLAG_INTERNAL_API | NM_FLAG_HIDDEN);
    if (ret) {
        nm_err("Failed to register NoMount Internal API (err: %d)\n", ret);
        kmem_cache_destroy(nm_dir_cachep);
        kmem_cache_destroy(nm_inode_cachep);
        put_cred(nm_root_cred);
        return ret;
    }

    nm_info("Loaded successfully\n");
    return 0;
}

static void __exit nomount_exit(void)
{
    mutex_lock(&nomount_write_mutex);
    __nomount_clear_all();
    mutex_unlock(&nomount_write_mutex);

    kmem_cache_destroy(nm_dir_cachep);
    kmem_cache_destroy(nm_inode_cachep);
    put_cred(nm_root_cred);

    nm_info("Unloaded successfully\n");
}

MODULE_LICENSE("GPL");
MODULE_VERSION(NM_MODULE_VERSION);
MODULE_AUTHOR("maxsteeel");
MODULE_DESCRIPTION("NoMount Path Redirection VFS Subsystem");

fs_initcall(nomount_init);
module_exit(nomount_exit);
