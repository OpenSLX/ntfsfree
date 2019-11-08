#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>

#include "config.h"
#include <ntfs-3g/volume.h>
#include <ntfs-3g/dir.h>

#define PFMAX (10)
static struct {
	s64 from;
	s64 to;
} pagefile[PFMAX];
static int pfcount = 0;

static struct {
	s64 min_size;
	int human;
	int brief;
	int force;
	int pagefile;
	int output_block_size;
	char *device;
} options;

static int utils_valid_device(const char *name, int force);
static ntfs_volume * utils_mount_volume(const char *device, unsigned long flags);
ATTR_RECORD * find_attribute(const ATTR_TYPES type, ntfs_attr_search_ctx *ctx);
static int utils_cluster_in_use(ntfs_volume *vol, long long lcn);
static int scan_free_space(ntfs_volume *vol);
static int get_pagefile_clusters(ntfs_volume *vol);

// Params
//
//
static int parse_options(int argc, char **argv)
{
	static const char *sopt = "-m:hbfps:";
	static const struct option lopt[] = {
		{ "block-size", required_argument,      NULL, 's' },
		{ "min-size",	required_argument,	NULL, 'm' },
		{ "human-readable",	no_argument,	NULL, 'h' },
		{ "brief",	no_argument,		NULL, 'b' },
		{ "force",	no_argument,		NULL, 'f' },
		{ "pagefile",	no_argument,		NULL, 'p' },
		{ NULL,		0,			NULL, 0   }
	};

	int c = -1;
	int help = 0;
	char *end = NULL;

	opterr = 0; /* We'll handle the errors, thank you. */

	options.min_size = 500000000;
	options.human = 0;
	options.brief = 0;
	options.force = 0;
	options.pagefile = 0;
	options.output_block_size = 1;
	options.device = NULL;

	while ((c = getopt_long(argc, argv, sopt, lopt, NULL)) != -1) {
		switch (c) {
		case 1:	/* A non-option argument */
			if (options.device == NULL) {
				options.device = argv[optind-1];
			} else {
				options.device = NULL;
				help = 1;
			}
			break;

		case 'b':
			options.brief = 1;
			break;
		case 'h':
			options.human = 1;
			break;
		case 'm':
			options.min_size = strtol(optarg, &end, 0);
			break;
		case 'f':
			options.force = 1;
			break;
		case 'p':
			options.pagefile = 1;
			break;
		case 's':
			options.output_block_size = strtol(optarg, &end, 0);
			break;
		default:
			ntfs_log_error("Unknown option '%s'.\n", argv[optind-1]);
			help = 1;
			break;
		}
		if (help) break;
	}

	if (help || options.min_size < 0 || options.output_block_size < 1) {
		ntfs_log_error("Usage: %s [-m|--min-size <bytes>] [-h|--human-readable] [-b|--brief] [-p|--pagefile] [-s|--block-size <bytes>] <device>\n", argv[0]);
	}

	return help;
}

// Main
//
//

int main(int argc, char **argv)
{
	ntfs_volume *vol;
	int flags = NTFS_MNT_RDONLY;
	int ret = 0;
	//
	ntfs_log_set_handler(ntfs_log_handler_outerr);
	if (parse_options(argc, argv) != 0) {
		return 1;
	}
	if (options.force) {
		flags |= NTFS_MNT_RECOVER;
	}
	//
	vol = utils_mount_volume(options.device, flags);
	if (vol == NULL) {
		ntfs_log_error("Device '%s' not found.\n", options.device);
		return 1;
	}
	if (options.human) {
		ntfs_log_info("# Clustersize %u\n", (unsigned int)vol->cluster_size);
		ntfs_log_info("# Output block size %u\n", (unsigned int)options.output_block_size);
	}
	options.min_size /= vol->cluster_size;
	if (options.pagefile) {
		ret = get_pagefile_clusters(vol);
	}
	if (ret >= 0) {
		ret = scan_free_space(vol);
	}
	ntfs_umount(vol, FALSE);
	return ret > 0 ? 0 : 2;
}

// Helpers
//
//

// Based on ntfsprogs/utils.*
static int utils_valid_device(const char *name, int force)
{
	unsigned long mnt_flags = 0;
	struct stat st;

	if (!name) {
		errno = EINVAL;
		return 0;
	}

	if (stat(name, &st) == -1) {
		if (errno == ENOENT)
			ntfs_log_error("The device %s doesn't exist\n", name);
		else
			ntfs_log_perror("Error getting information about %s",
					name);
		return 0;
	}

	/* Make sure the file system is not mounted. */
	if (ntfs_check_if_mounted(name, &mnt_flags)) {
		ntfs_log_perror("Failed to determine whether %s is mounted",
				name);
		if (!force) {
			ntfs_log_error("Use the force option to ignore this "
					"error.\n");
			return 0;
		}
		ntfs_log_warning("Forced to continue.\n");
	} else if (mnt_flags & NTFS_MF_MOUNTED) {
		if (!force) {
			ntfs_log_error("Volume already mounted or in use otherwise.\n");
			ntfs_log_error("You can use force option to avoid this "
					"check, but this is not recommended\n"
					"and may lead to data corruption.\n");
			return 0;
		}
		ntfs_log_warning("Forced to continue.\n");
	}

	return 1;
}

/**
 * utils_mount_volume - Mount an NTFS volume
 * Based on ntfsprogs/utils.*
 */
static ntfs_volume * utils_mount_volume(const char *device, unsigned long flags)
{
	ntfs_volume *vol;

	if (!device) {
		errno = EINVAL;
		return NULL;
	}

	if (!utils_valid_device(device, flags & NTFS_MNT_RECOVER))
		return NULL;

	vol = ntfs_mount(device, flags);
	if (!vol) {
		ntfs_log_perror("Failed to mount '%s'", device);
		if (errno == EINVAL)
			ntfs_log_error("%s: Not an NTFS device.\n", device);
		else if (errno == EIO)
			ntfs_log_error("Corrupted volume. Run chkdsk /f.\n");
		else if (errno == EPERM)
			ntfs_log_error("This volume is hibernated. Please shut down Windows properly.\n");
		else if (errno == EOPNOTSUPP)
			ntfs_log_error("NTFS journal is unclean.\n");
		else if (errno == EBUSY)
			ntfs_log_error("%s", "Busy: Volume already in use.\n");
		else if (errno == ENXIO)
			ntfs_log_error("SoftRAID/FakeRAID is not supported.\n");
		return NULL;
	}

	if (vol->flags & VOLUME_IS_DIRTY) {
		if (!(flags & NTFS_MNT_RECOVER)) {
			ntfs_log_error("Volume is marked dirty, plase boot windows first.\n");
			ntfs_umount(vol, FALSE);
			return NULL;
		}
		ntfs_log_error("WARNING: Dirty volume mount was forced by the "
				"'force' mount option.\n");
	}
	return vol;
}

ATTR_RECORD * find_attribute(const ATTR_TYPES type, ntfs_attr_search_ctx *ctx)
{
	if (!ctx) {
		errno = EINVAL;
		return NULL;
	}

	if (ntfs_attr_lookup(type, NULL, 0, 0, 0, NULL, 0, ctx) != 0) {
		ntfs_log_debug("find_attribute didn't find an attribute of type: 0x%02x.\n", le32_to_cpu(type));
		return NULL;	/* None / no more of that type */
	}

	ntfs_log_debug("find_attribute found an attribute of type: 0x%02x.\n", le32_to_cpu(type));
	return ctx->attr;
}

// Taken from ntfsprogs/utils.c
static int utils_cluster_in_use(ntfs_volume *vol, long long lcn)
{
	static unsigned char buffer[512];
	static long long bmplcn = -(sizeof(buffer) << 3);
	int byte, bit;
	ntfs_attr *attr;

	if (!vol) {
		errno = EINVAL;
		return -1;
	}

	/* Does lcn lie in the section of $Bitmap we already have cached? */
	if ((lcn < bmplcn)
	    || (lcn >= (long long)(bmplcn + (sizeof(buffer) << 3)))) {
		ntfs_log_debug("Bit lies outside cache.\n");
		attr = ntfs_attr_open(vol->lcnbmp_ni, AT_DATA, AT_UNNAMED, 0);
		if (!attr) {
			ntfs_log_perror("Couldn't open $Bitmap");
			return -1;
		}

		/* Mark the buffer as in use, in case the read is shorter. */
		memset(buffer, 0xFF, sizeof(buffer));
		bmplcn = lcn & (~((sizeof(buffer) << 3) - 1));

		if (ntfs_attr_pread(attr, (bmplcn >> 3), sizeof(buffer),
					buffer) < 0) {
			ntfs_log_perror("Couldn't read $Bitmap");
			ntfs_attr_close(attr);
			return -1;
		}

		ntfs_log_debug("Reloaded bitmap buffer.\n");
		ntfs_attr_close(attr);
	}

	bit  = 1 << (lcn & 7);
	byte = (lcn >> 3) & (sizeof(buffer) - 1);
	ntfs_log_debug("cluster = %lld, bmplcn = %lld, byte = %d, bit = %d, "
			"in use %d\n", lcn, bmplcn, byte, bit, buffer[byte] &
			bit);

	return (buffer[byte] & bit);
}

#define TOBLOCK(x) ( (x) * vol->cluster_size / options.output_block_size )
#define TOSIZE(x) ( options.human ? ( (x) / (1024 * 1024 / vol->cluster_size) ) : TOBLOCK(x) )

static int scan_free_space(ntfs_volume *vol)
{
	s64 i, j;
	s64 curStart = -1;
	s64 start = 0;
	s64 end = 0;
	int pf;
	const char *message = NULL;
	const char *summary = NULL;

	if (!vol)
		return -1;

	if (options.brief) {
		if (options.human) {
			summary = "Biggest range from %lld to %lld, %lldMiB\n";
		} else {
			summary = "Biggest %lld %lld %lld\n";
		}
	} else {
		if (options.human) {
			message = "Range from %lld to %lld, %lldMiB\n";
		} else {
			message = "Range %lld %lld %lld\n";
		}
	}

	for (i = 0; i <= vol->nr_clusters; i++) {
		pf = 0;
		for (j = 0; j < pfcount; ++j) {
			if (i >= pagefile[j].from && i <= pagefile[j].to) {
				pf = 1;
				break;
			}
		}
		if (i == vol->nr_clusters || (!pf && utils_cluster_in_use(vol, i))) {
			if (curStart != -1) {
				if (i - curStart > options.min_size) {
					if (message != NULL) {
						ntfs_log_info(message, (long long)TOBLOCK(curStart), (long long)TOBLOCK(i), (long long)TOSIZE(i - curStart));
					}
					if (i - curStart > end - start) {
						start = curStart;
						end = i;
					}
				}
			}
			curStart = -1;
		} else if (curStart == -1) {
			curStart = i;
		}
	}

	if (summary != NULL) {
		ntfs_log_info("Biggest range from %lld to %lld, %lldMiB\n", (long long)TOBLOCK(start), (long long)TOBLOCK(end), (long long)TOSIZE(end - start));
	}
	return 1;
}

static int get_pagefile_clusters(ntfs_volume *vol)
{
	ntfs_inode *ni = NULL;
	ntfs_attr *na = NULL;
	ntfs_attr_search_ctx *ctx;
	int returnCode = 0;
	ATTR_RECORD *rec;
	int i, clusters;
	runlist *runs;

	ni = ntfs_pathname_to_inode(vol, NULL, "pagefile.sys");
	if (!ni) {
		ntfs_log_debug("Failed to open inode of pagefile.sys.\n");
		return 0;
	}

	if ((na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0)) == NULL) {
		ntfs_log_debug("Failed to open pagefile.sys/$DATA.\n");
		goto error_exit;
	}

	/* The $DATA attribute of the pagefile.sys has to be non-resident. */
	if (!NAttrNonResident(na)) {
		ntfs_log_warning("pagefile.sys $DATA attribute is resident!?!\n");
		goto error_exit;
	}

	/* Get length of pagefile.sys contents. */
	clusters = (na->data_size + (vol->cluster_size - 1)) / vol->cluster_size;
	if (clusters == 0) {
		ntfs_log_warning("pagefile.sys has zero length.\n");
		goto real_exit;
	}

	if ((na->data_flags & ATTR_COMPRESSION_MASK) != const_cpu_to_le16(0)) {
		ntfs_log_warning("pagefile.sys is compressed!?\n");
		goto real_exit;
	}
	ntfs_attr_close(na);
	na = NULL;

	// Get complete runlist
	ctx = ntfs_attr_get_search_ctx(ni, NULL);

	while (pfcount < PFMAX && (rec = find_attribute(AT_DATA, ctx))) {
		if (rec->non_resident) {
			runs = ntfs_mapping_pairs_decompress(vol, rec, NULL);
			if (runs) {
				for (i = 0; runs[i].length > 0; i++) {
					pagefile[pfcount].from = runs[i].lcn;
					pagefile[pfcount].to = runs[i].lcn + (runs[i].length - 1);
					pfcount++;
				}
				free(runs);
			}
		}
	}
	ntfs_attr_put_search_ctx(ctx);

	// All done
	goto real_exit;
error_exit:
	returnCode = -1;
real_exit:
	if (na != NULL) {
		ntfs_attr_close(na);
	}
	if (ni != NULL) {
		ntfs_inode_close(ni);
	}
	return returnCode;

}

