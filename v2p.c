#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

#define PAGE_SIZE 4096

static int can_merge(struct vm_area *prev, struct vm_area *next)
{
    return (prev->vm_end == next->vm_start) && (prev->access_flags == next->access_flags);
}

static struct vm_area *create_vma(u64 start, u64 end, int prot)
{
    struct vm_area *new_vma = os_alloc(sizeof(struct vm_area));
    new_vma->vm_start = start;
    new_vma->vm_end = end;
    new_vma->access_flags = prot;
    new_vma->vm_next = NULL;
    stats->num_vm_area++;
    return new_vma;
}

/**
 * mprotect System call Implementation.
 */
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if (addr < MMAP_AREA_START || addr >= MMAP_AREA_END)
    {
        return -EINVAL;
    }
    if (prot != PROT_READ && prot != (PROT_READ | PROT_WRITE))
    {
        return -EINVAL;
    }

    u64 end = addr + ((length + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
    struct vm_area *prev = current->vm_area;
    struct vm_area *curr = prev->vm_next;

    while (curr && curr->vm_start < end)
    {
        if (curr->vm_end <= addr)
        {
            prev = curr;
            curr = curr->vm_next;
            continue;
        }

        if (addr <= curr->vm_start && curr->vm_end <= end)
        {
            curr->access_flags = prot;
            if (prev != current->vm_area && can_merge(prev, curr))
            {
                prev->vm_end = curr->vm_end;
                prev->vm_next = curr->vm_next;
                os_free(curr, sizeof(struct vm_area));
                stats->num_vm_area--;
                curr = prev->vm_next;
            }
            else
            {
                struct vm_area *next = curr->vm_next;
                if (next && can_merge(curr, next))
                {
                    curr->vm_end = next->vm_end;
                    curr->vm_next = next->vm_next;
                    os_free(next, sizeof(struct vm_area));
                    stats->num_vm_area--;
                }
                prev = curr;
                curr = curr->vm_next;
            }
            continue;
        }

        if (curr->vm_start < addr && curr->vm_end > end)
        {
            struct vm_area *middle = create_vma(addr, end, prot);
            struct vm_area *right = create_vma(end, curr->vm_end, curr->access_flags);
            curr->vm_end = addr;
            right->vm_next = curr->vm_next;
            middle->vm_next = right;
            curr->vm_next = middle;
            break;
        }

        if (addr <= curr->vm_start && end < curr->vm_end)
        {
            struct vm_area *new_vma = create_vma(curr->vm_start, end, prot);
            curr->vm_start = end;
            new_vma->vm_next = curr;
            prev->vm_next = new_vma;

            if (prev != current->vm_area && can_merge(prev, new_vma))
            {
                prev->vm_end = new_vma->vm_end;
                prev->vm_next = curr;
                os_free(new_vma, sizeof(struct vm_area));
                stats->num_vm_area--;
            }
            break;
        }

        if (curr->vm_start < addr && curr->vm_end <= end)
        {
            struct vm_area *new_vma = create_vma(addr, curr->vm_end, prot);
            curr->vm_end = addr;
            new_vma->vm_next = curr->vm_next;
            curr->vm_next = new_vma;

            prev = curr;
            curr = new_vma;
            if (curr->vm_next && can_merge(curr, curr->vm_next))
            {
                struct vm_area *next = curr->vm_next;
                curr->vm_end = next->vm_end;
                curr->vm_next = next->vm_next;
                os_free(next, sizeof(struct vm_area));
                stats->num_vm_area--;
            }
        }
    }

    return 0;
}

/**
 * mmap system call implementation.
 */
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    if (prot != PROT_READ && prot != (PROT_READ | PROT_WRITE))
    {
        return -EINVAL;
    }
    if (flags != 0 && flags != MAP_FIXED)
    {
        return -EINVAL;
    }
    if (addr != 0 && (addr < MMAP_AREA_START || addr >= MMAP_AREA_END))
    {
        return -EINVAL;
    }
    if (flags == MAP_FIXED && addr == 0)
    {
        return -EINVAL;
    }

    if (!current->vm_area)
    {
        current->vm_area = create_vma(MMAP_AREA_START, MMAP_AREA_START + PAGE_SIZE, 0);
    }

    u64 len = (length + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    u64 start = addr;
    u64 end = start + len;

    if (addr == 0)
    {
        start = MMAP_AREA_START + PAGE_SIZE;
        struct vm_area *prev = current->vm_area;
        struct vm_area *curr = prev->vm_next;

        while (curr && curr->vm_start < start + len)
        {
            if (start + len <= curr->vm_start)
            {
                break;
            }
            start = curr->vm_end;
            prev = curr;
            curr = curr->vm_next;
        }

        if (start + len > MMAP_AREA_END)
        {
            return -EINVAL;
        }
        end = start + len;
    }

    struct vm_area *prev = current->vm_area;
    struct vm_area *curr = prev->vm_next;
    struct vm_area *merge_prev = NULL;
    struct vm_area *merge_next = NULL;

    while (curr)
    {
        if (curr->vm_end <= start)
        {
            prev = curr;
            curr = curr->vm_next;
            continue;
        }
        if (end <= curr->vm_start)
            break;

        if (flags == MAP_FIXED)
        {
            return -EINVAL;
        }
        if (addr != 0)
        {
            return vm_area_map(current, 0, length, prot, 0);
        }
        return -EINVAL;
    }

    if (prev != current->vm_area && prev->vm_end == start && prev->access_flags == prot)
    {
        merge_prev = prev;
    }
    if (curr && end == curr->vm_start && curr->access_flags == prot)
    {
        merge_next = curr;
    }

    u64 ret_addr = start;

    if (merge_prev && merge_next)
    {
        merge_prev->vm_end = merge_next->vm_end;
        merge_prev->vm_next = merge_next->vm_next;
        os_free(merge_next, sizeof(struct vm_area));
        stats->num_vm_area--;
    }
    else if (merge_prev)
    {
        merge_prev->vm_end = end;
    }
    else if (merge_next)
    {
        merge_next->vm_start = start;
    }
    else
    {
        struct vm_area *new_vma = create_vma(start, end, prot);
        new_vma->vm_next = curr;
        prev->vm_next = new_vma;
    }

    return ret_addr;
}

/**
 * munmap system call implemenations
 */
long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if (addr < MMAP_AREA_START || addr >= MMAP_AREA_END)
    {
        return -EINVAL;
    }

    u64 end = addr + ((length + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));

    struct vm_area *prev = current->vm_area;
    struct vm_area *curr = prev->vm_next;

    while (curr && curr->vm_start < end)
    {
        if (curr->vm_end <= addr)
        {
            prev = curr;
            curr = curr->vm_next;
            continue;
        }

        if (addr <= curr->vm_start && curr->vm_end <= end)
        {
            prev->vm_next = curr->vm_next;
            os_free(curr, sizeof(struct vm_area));
            stats->num_vm_area--;
            curr = prev->vm_next;
            continue;
        }

        if (curr->vm_start < addr && curr->vm_end > end)
        {
            struct vm_area *new_vma = create_vma(end, curr->vm_end, curr->access_flags);

            curr->vm_end = addr;
            new_vma->vm_next = curr->vm_next;
            curr->vm_next = new_vma;
            break;
        }

        if (addr <= curr->vm_start && end < curr->vm_end)
        {
            curr->vm_start = end;
            break;
        }

        if (curr->vm_start < addr && curr->vm_end <= end)
        {
            curr->vm_end = addr;
            prev = curr;
            curr = curr->vm_next;
        }
    }

    return 0;
}

/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */
long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    return -1;
}

/**
 * cfork system call implementations
 */
long do_cfork()
{
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();

    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    return -1;
}