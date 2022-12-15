/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2011, 2015 by Delphix. All rights reserved.
 * Copyright (c) 2013 Steven Hartland. All rights reserved.
 */

/*
 * zhack is a debugging tool that can write changes to ZFS pool using libzpool
 * for testing purposes. Altering pools with zhack is unsupported and may
 * result in corrupted pools.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/dmu.h>
#include <sys/zap.h>
#include <sys/zfs_znode.h>
#include <sys/dsl_synctask.h>
#include <sys/vdev.h>
#include <sys/vdev_impl.h>
#include <sys/fs/zfs.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_pool.h>
#include <sys/zio_checksum.h>
#include <sys/zio_compress.h>
#include <sys/zfeature.h>
#include <sys/dmu_tx.h>
#include <zfeature_common.h>
#include <libzutil.h>
#include <libnvpair.h>

static importargs_t g_importargs;
static char *g_pool;
static boolean_t g_readonly;

static __attribute__((noreturn)) void
usage(void)
{
	(void) fprintf(stderr,
	    "Usage: zhack [-c cachefile] [-d dir] <subcommand> <args> ...\n"
	    "where <subcommand> <args> is one of the following:\n"
	    "\n");

	(void) fprintf(stderr,
	    "    feature stat <pool>\n"
	    "        print information about enabled features\n"
	    "    feature enable [-r] [-d desc] <pool> <feature>\n"
	    "        add a new enabled feature to the pool\n"
	    "        -d <desc> sets the feature's description\n"
	    "        -r set read-only compatible flag for feature\n"
	    "    feature ref [-md] <pool> <feature>\n"
	    "        change the refcount on the given feature\n"
	    "        -d decrease instead of increase the refcount\n"
	    "        -m add the feature to the label if increasing refcount\n"
	    "\n"
	    "    <feature> : should be a feature guid\n"
	    "\n"
	    "    label repair <device>\n"
	    "        repair corrupted label checksums\n"
	    "\n"
	    "    <device> : path to vdev\n");
	exit(1);
}


static __attribute__((format(printf, 3, 4))) __attribute__((noreturn)) void
fatal(spa_t *spa, const void *tag, const char *fmt, ...)
{
	va_list ap;

	if (spa != NULL) {
		spa_close(spa, tag);
		(void) spa_export(g_pool, NULL, B_TRUE, B_FALSE);
	}

	va_start(ap, fmt);
	(void) fputs("zhack: ", stderr);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	(void) fputc('\n', stderr);

	exit(1);
}

static int
space_delta_cb(dmu_object_type_t bonustype, const void *data,
    zfs_file_info_t *zoi)
{
	(void) data, (void) zoi;

	/*
	 * Is it a valid type of object to track?
	 */
	if (bonustype != DMU_OT_ZNODE && bonustype != DMU_OT_SA)
		return (ENOENT);
	(void) fprintf(stderr, "modifying object that needs user accounting");
	abort();
}

/*
 * Target is the dataset whose pool we want to open.
 */
static void
zhack_import(char *target, boolean_t readonly)
{
	nvlist_t *config;
	nvlist_t *props;
	int error;

	kernel_init(readonly ? SPA_MODE_READ :
	    (SPA_MODE_READ | SPA_MODE_WRITE));

	dmu_objset_register_type(DMU_OST_ZFS, space_delta_cb);

	g_readonly = readonly;
	g_importargs.can_be_active = readonly;
	g_pool = strdup(target);

	libpc_handle_t lpch = {
		.lpc_lib_handle = NULL,
		.lpc_ops = &libzpool_config_ops,
		.lpc_printerr = B_TRUE
	};
	error = zpool_find_config(&lpch, target, &config, &g_importargs);
	if (error)
		fatal(NULL, FTAG, "cannot import '%s'", target);

	props = NULL;
	if (readonly) {
		VERIFY(nvlist_alloc(&props, NV_UNIQUE_NAME, 0) == 0);
		VERIFY(nvlist_add_uint64(props,
		    zpool_prop_to_name(ZPOOL_PROP_READONLY), 1) == 0);
	}

	zfeature_checks_disable = B_TRUE;
	error = spa_import(target, config, props,
	    (readonly ?  ZFS_IMPORT_SKIP_MMP : ZFS_IMPORT_NORMAL));
	fnvlist_free(config);
	zfeature_checks_disable = B_FALSE;
	if (error == EEXIST)
		error = 0;

	if (error)
		fatal(NULL, FTAG, "can't import '%s': %s", target,
		    strerror(error));
}

static void
zhack_spa_open(char *target, boolean_t readonly, const void *tag, spa_t **spa)
{
	int err;

	zhack_import(target, readonly);

	zfeature_checks_disable = B_TRUE;
	err = spa_open(target, spa, tag);
	zfeature_checks_disable = B_FALSE;

	if (err != 0)
		fatal(*spa, FTAG, "cannot open '%s': %s", target,
		    strerror(err));
	if (spa_version(*spa) < SPA_VERSION_FEATURES) {
		fatal(*spa, FTAG, "'%s' has version %d, features not enabled",
		    target, (int)spa_version(*spa));
	}
}

static void
dump_obj(objset_t *os, uint64_t obj, const char *name)
{
	zap_cursor_t zc;
	zap_attribute_t za;

	(void) printf("%s_obj:\n", name);

	for (zap_cursor_init(&zc, os, obj);
	    zap_cursor_retrieve(&zc, &za) == 0;
	    zap_cursor_advance(&zc)) {
		if (za.za_integer_length == 8) {
			ASSERT(za.za_num_integers == 1);
			(void) printf("\t%s = %llu\n",
			    za.za_name, (u_longlong_t)za.za_first_integer);
		} else {
			ASSERT(za.za_integer_length == 1);
			char val[1024];
			VERIFY(zap_lookup(os, obj, za.za_name,
			    1, sizeof (val), val) == 0);
			(void) printf("\t%s = %s\n", za.za_name, val);
		}
	}
	zap_cursor_fini(&zc);
}

static void
dump_mos(spa_t *spa)
{
	nvlist_t *nv = spa->spa_label_features;
	nvpair_t *pair;

	(void) printf("label config:\n");
	for (pair = nvlist_next_nvpair(nv, NULL);
	    pair != NULL;
	    pair = nvlist_next_nvpair(nv, pair)) {
		(void) printf("\t%s\n", nvpair_name(pair));
	}
}

static void
zhack_do_feature_stat(int argc, char **argv)
{
	spa_t *spa;
	objset_t *os;
	char *target;

	argc--;
	argv++;

	if (argc < 1) {
		(void) fprintf(stderr, "error: missing pool name\n");
		usage();
	}
	target = argv[0];

	zhack_spa_open(target, B_TRUE, FTAG, &spa);
	os = spa->spa_meta_objset;

	dump_obj(os, spa->spa_feat_for_read_obj, "for_read");
	dump_obj(os, spa->spa_feat_for_write_obj, "for_write");
	dump_obj(os, spa->spa_feat_desc_obj, "descriptions");
	if (spa_feature_is_active(spa, SPA_FEATURE_ENABLED_TXG)) {
		dump_obj(os, spa->spa_feat_enabled_txg_obj, "enabled_txg");
	}
	dump_mos(spa);

	spa_close(spa, FTAG);
}

static void
zhack_feature_enable_sync(void *arg, dmu_tx_t *tx)
{
	spa_t *spa = dmu_tx_pool(tx)->dp_spa;
	zfeature_info_t *feature = arg;

	feature_enable_sync(spa, feature, tx);

	spa_history_log_internal(spa, "zhack enable feature", tx,
	    "name=%s flags=%u",
	    feature->fi_guid, feature->fi_flags);
}

static void
zhack_do_feature_enable(int argc, char **argv)
{
	int c;
	char *desc, *target;
	spa_t *spa;
	objset_t *mos;
	zfeature_info_t feature;
	const spa_feature_t nodeps[] = { SPA_FEATURE_NONE };

	/*
	 * Features are not added to the pool's label until their refcounts
	 * are incremented, so fi_mos can just be left as false for now.
	 */
	desc = NULL;
	feature.fi_uname = "zhack";
	feature.fi_flags = 0;
	feature.fi_depends = nodeps;
	feature.fi_feature = SPA_FEATURE_NONE;

	optind = 1;
	while ((c = getopt(argc, argv, "+rd:")) != -1) {
		switch (c) {
		case 'r':
			feature.fi_flags |= ZFEATURE_FLAG_READONLY_COMPAT;
			break;
		case 'd':
			if (desc != NULL)
				free(desc);
			desc = strdup(optarg);
			break;
		default:
			usage();
			break;
		}
	}

	if (desc == NULL)
		desc = strdup("zhack injected");
	feature.fi_desc = desc;

	argc -= optind;
	argv += optind;

	if (argc < 2) {
		(void) fprintf(stderr, "error: missing feature or pool name\n");
		usage();
	}
	target = argv[0];
	feature.fi_guid = argv[1];

	if (!zfeature_is_valid_guid(feature.fi_guid))
		fatal(NULL, FTAG, "invalid feature guid: %s", feature.fi_guid);

	zhack_spa_open(target, B_FALSE, FTAG, &spa);
	mos = spa->spa_meta_objset;

	if (zfeature_is_supported(feature.fi_guid))
		fatal(spa, FTAG, "'%s' is a real feature, will not enable",
		    feature.fi_guid);
	if (0 == zap_contains(mos, spa->spa_feat_desc_obj, feature.fi_guid))
		fatal(spa, FTAG, "feature already enabled: %s",
		    feature.fi_guid);

	VERIFY0(dsl_sync_task(spa_name(spa), NULL,
	    zhack_feature_enable_sync, &feature, 5, ZFS_SPACE_CHECK_NORMAL));

	spa_close(spa, FTAG);

	free(desc);
}

static void
feature_incr_sync(void *arg, dmu_tx_t *tx)
{
	spa_t *spa = dmu_tx_pool(tx)->dp_spa;
	zfeature_info_t *feature = arg;
	uint64_t refcount;

	VERIFY0(feature_get_refcount_from_disk(spa, feature, &refcount));
	feature_sync(spa, feature, refcount + 1, tx);
	spa_history_log_internal(spa, "zhack feature incr", tx,
	    "name=%s", feature->fi_guid);
}

static void
feature_decr_sync(void *arg, dmu_tx_t *tx)
{
	spa_t *spa = dmu_tx_pool(tx)->dp_spa;
	zfeature_info_t *feature = arg;
	uint64_t refcount;

	VERIFY0(feature_get_refcount_from_disk(spa, feature, &refcount));
	feature_sync(spa, feature, refcount - 1, tx);
	spa_history_log_internal(spa, "zhack feature decr", tx,
	    "name=%s", feature->fi_guid);
}

static void
zhack_do_feature_ref(int argc, char **argv)
{
	int c;
	char *target;
	boolean_t decr = B_FALSE;
	spa_t *spa;
	objset_t *mos;
	zfeature_info_t feature;
	const spa_feature_t nodeps[] = { SPA_FEATURE_NONE };

	/*
	 * fi_desc does not matter here because it was written to disk
	 * when the feature was enabled, but we need to properly set the
	 * feature for read or write based on the information we read off
	 * disk later.
	 */
	feature.fi_uname = "zhack";
	feature.fi_flags = 0;
	feature.fi_desc = NULL;
	feature.fi_depends = nodeps;
	feature.fi_feature = SPA_FEATURE_NONE;

	optind = 1;
	while ((c = getopt(argc, argv, "+md")) != -1) {
		switch (c) {
		case 'm':
			feature.fi_flags |= ZFEATURE_FLAG_MOS;
			break;
		case 'd':
			decr = B_TRUE;
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2) {
		(void) fprintf(stderr, "error: missing feature or pool name\n");
		usage();
	}
	target = argv[0];
	feature.fi_guid = argv[1];

	if (!zfeature_is_valid_guid(feature.fi_guid))
		fatal(NULL, FTAG, "invalid feature guid: %s", feature.fi_guid);

	zhack_spa_open(target, B_FALSE, FTAG, &spa);
	mos = spa->spa_meta_objset;

	if (zfeature_is_supported(feature.fi_guid)) {
		fatal(spa, FTAG,
		    "'%s' is a real feature, will not change refcount",
		    feature.fi_guid);
	}

	if (0 == zap_contains(mos, spa->spa_feat_for_read_obj,
	    feature.fi_guid)) {
		feature.fi_flags &= ~ZFEATURE_FLAG_READONLY_COMPAT;
	} else if (0 == zap_contains(mos, spa->spa_feat_for_write_obj,
	    feature.fi_guid)) {
		feature.fi_flags |= ZFEATURE_FLAG_READONLY_COMPAT;
	} else {
		fatal(spa, FTAG, "feature is not enabled: %s", feature.fi_guid);
	}

	if (decr) {
		uint64_t count;
		if (feature_get_refcount_from_disk(spa, &feature,
		    &count) == 0 && count == 0) {
			fatal(spa, FTAG, "feature refcount already 0: %s",
			    feature.fi_guid);
		}
	}

	VERIFY0(dsl_sync_task(spa_name(spa), NULL,
	    decr ? feature_decr_sync : feature_incr_sync, &feature,
	    5, ZFS_SPACE_CHECK_NORMAL));

	spa_close(spa, FTAG);
}

static int
zhack_do_feature(int argc, char **argv)
{
	char *subcommand;

	argc--;
	argv++;
	if (argc == 0) {
		(void) fprintf(stderr,
		    "error: no feature operation specified\n");
		usage();
	}

	subcommand = argv[0];
	if (strcmp(subcommand, "stat") == 0) {
		zhack_do_feature_stat(argc, argv);
	} else if (strcmp(subcommand, "enable") == 0) {
		zhack_do_feature_enable(argc, argv);
	} else if (strcmp(subcommand, "ref") == 0) {
		zhack_do_feature_ref(argc, argv);
	} else {
		(void) fprintf(stderr, "error: unknown subcommand: %s\n",
		    subcommand);
		usage();
	}

	return (0);
}

static int
zhack_repair_label_cksum(int argc, char **argv)
{
	zio_checksum_info_t *ci = &zio_checksum_table[ZIO_CHECKSUM_LABEL];
	const char *cfg_keys[] = { ZPOOL_CONFIG_VERSION,
	    ZPOOL_CONFIG_POOL_STATE, ZPOOL_CONFIG_GUID };
	boolean_t labels_repaired[VDEV_LABELS] = {0};
	boolean_t repaired = B_FALSE;
	vdev_label_t labels[VDEV_LABELS] = {{{0}}};
	struct stat st;
	int fd;

	abd_init();

	argc -= 1;
	argv += 1;

	if (argc < 1) {
		(void) fprintf(stderr, "error: missing device\n");
		usage();
	}

	if ((fd = open(argv[0], O_RDWR)) == -1)
		fatal(NULL, FTAG, "cannot open '%s': %s", argv[0],
		    strerror(errno));

	if (stat(argv[0], &st) != 0)
		fatal(NULL, FTAG, "cannot stat '%s': %s", argv[0],
		    strerror(errno));

	for (int l = 0; l < VDEV_LABELS; l++) {
		uint64_t label_offset, offset;
		zio_cksum_t expected_cksum;
		zio_cksum_t actual_cksum;
		zio_cksum_t verifier;
		zio_eck_t *eck;
		nvlist_t *cfg;
		int byteswap;
		uint64_t val;
		ssize_t err;

		vdev_label_t *vl = &labels[l];

		label_offset = vdev_label_offset(st.st_size, l, 0);
		err = pread64(fd, vl, sizeof (vdev_label_t), label_offset);
		if (err == -1) {
			(void) fprintf(stderr, "error: cannot read "
			    "label %d: %s\n", l, strerror(errno));
			continue;
		} else if (err != sizeof (vdev_label_t)) {
			(void) fprintf(stderr, "error: bad label %d read size "
			    "\n", l);
			continue;
		}

		err = nvlist_unpack(vl->vl_vdev_phys.vp_nvlist,
		    VDEV_PHYS_SIZE - sizeof (zio_eck_t), &cfg, 0);
		if (err) {
			(void) fprintf(stderr, "error: cannot unpack nvlist "
			    "label %d\n", l);
			continue;
		}

		for (int i = 0; i < ARRAY_SIZE(cfg_keys); i++) {
			err = nvlist_lookup_uint64(cfg, cfg_keys[i], &val);
			if (err) {
				(void) fprintf(stderr, "error: label %d: "
				    "cannot find nvlist key %s\n",
				    l, cfg_keys[i]);
				continue;
			}
		}

		void *data = (char *)vl + offsetof(vdev_label_t, vl_vdev_phys);
		eck = (zio_eck_t *)((char *)(data) + VDEV_PHYS_SIZE) - 1;

		offset = label_offset + offsetof(vdev_label_t, vl_vdev_phys);
		ZIO_SET_CHECKSUM(&verifier, offset, 0, 0, 0);

		byteswap = (eck->zec_magic == BSWAP_64(ZEC_MAGIC));
		if (byteswap)
			byteswap_uint64_array(&verifier, sizeof (zio_cksum_t));

		expected_cksum = eck->zec_cksum;
		eck->zec_cksum = verifier;

		abd_t *abd = abd_get_from_buf(data, VDEV_PHYS_SIZE);
		ci->ci_func[byteswap](abd, VDEV_PHYS_SIZE, NULL, &actual_cksum);
		abd_free(abd);

		if (byteswap)
			byteswap_uint64_array(&expected_cksum,
			    sizeof (zio_cksum_t));

		if (ZIO_CHECKSUM_EQUAL(actual_cksum, expected_cksum))
			continue;

		eck->zec_cksum = actual_cksum;

		err = pwrite64(fd, data, VDEV_PHYS_SIZE, offset);
		if (err == -1) {
			(void) fprintf(stderr, "error: cannot write "
			    "label %d: %s\n", l, strerror(errno));
			continue;
		} else if (err != VDEV_PHYS_SIZE) {
			(void) fprintf(stderr, "error: bad write size "
			    "label %d\n", l);
			continue;
		}

		fsync(fd);

		labels_repaired[l] = B_TRUE;
	}

	close(fd);

	abd_fini();

	for (int l = 0; l < VDEV_LABELS; l++) {
		(void) printf("label %d: %s\n", l,
		    labels_repaired[l] ? "repaired" : "skipped");
		repaired |= labels_repaired[l];
	}

	if (repaired)
		return (0);

	return (1);
}

//stolen from libnvpair.c

#define	NVP(elem, type, vtype, ptype, format) { \
	vtype	value; \
\
	(void) nvpair_value_##type(elem, &value); \
	(void) printf("%*s%s: " format "\n", indent, "", \
	    nvpair_name(elem), (ptype)value); \
}

#define	NVPA(elem, type, vtype, ptype, format) { \
	uint_t	i, count; \
	vtype	*value;  \
\
	(void) nvpair_value_##type(elem, &value, &count); \
	for (i = 0; i < count; i++) { \
		(void) printf("%*s%s[%d]: " format "\n", indent, "", \
		    nvpair_name(elem), i, (ptype)value[i]); \
	} \
}
static void
zhack_print_nvpair(nvpair_t *elem, int indent )
{
	boolean_t	bool_value;
	switch (nvpair_type(elem)) {
		case DATA_TYPE_BOOLEAN:
			(void) printf("%*s%s\n", indent, "", nvpair_name(elem));
			break;

		case DATA_TYPE_BOOLEAN_VALUE:
			(void) nvpair_value_boolean_value(elem, &bool_value);
			(void) printf("%*s%s: %s\n", indent, "",
			    nvpair_name(elem), bool_value ? "true" : "false");
			break;

		case DATA_TYPE_BYTE:
			NVP(elem, byte, uchar_t, int, "%u");
			break;

		case DATA_TYPE_INT8:
			NVP(elem, int8, int8_t, int, "%d");
			break;

		case DATA_TYPE_UINT8:
			NVP(elem, uint8, uint8_t, int, "%u");
			break;

		case DATA_TYPE_INT16:
			NVP(elem, int16, int16_t, int, "%d");
			break;

		case DATA_TYPE_UINT16:
			NVP(elem, uint16, uint16_t, int, "%u");
			break;

		case DATA_TYPE_INT32:
			NVP(elem, int32, int32_t, long, "%ld");
			break;

		case DATA_TYPE_UINT32:
			NVP(elem, uint32, uint32_t, ulong_t, "%lu");
			break;

		case DATA_TYPE_INT64:
			NVP(elem, int64, int64_t, longlong_t, "%lld");
			break;

		case DATA_TYPE_UINT64:
			NVP(elem, uint64, uint64_t, u_longlong_t, "%llu");
			break;

		case DATA_TYPE_STRING:
			NVP(elem, string, char *, char *, "'%s'");
			break;

		case DATA_TYPE_BYTE_ARRAY:
			NVPA(elem, byte_array, uchar_t, int, "%u");
			break;

		case DATA_TYPE_INT8_ARRAY:
			NVPA(elem, int8_array, int8_t, int, "%d");
			break;

		case DATA_TYPE_UINT8_ARRAY:
			NVPA(elem, uint8_array, uint8_t, int, "%u");
			break;

		case DATA_TYPE_INT16_ARRAY:
			NVPA(elem, int16_array, int16_t, int, "%d");
			break;

		case DATA_TYPE_UINT16_ARRAY:
			NVPA(elem, uint16_array, uint16_t, int, "%u");
			break;

		case DATA_TYPE_INT32_ARRAY:
			NVPA(elem, int32_array, int32_t, long, "%ld");
			break;

		case DATA_TYPE_UINT32_ARRAY:
			NVPA(elem, uint32_array, uint32_t, ulong_t, "%lu");
			break;

		case DATA_TYPE_INT64_ARRAY:
			NVPA(elem, int64_array, int64_t, longlong_t, "%lld");
			break;

		case DATA_TYPE_UINT64_ARRAY:
			NVPA(elem, uint64_array, uint64_t, u_longlong_t,
			    "%llu");
			break;

		case DATA_TYPE_STRING_ARRAY:
			NVPA(elem, string_array, char *, char *, "'%s'");
			break;
/* we do not handle these
		case DATA_TYPE_NVLIST:
			(void) nvpair_value_nvlist(elem, &nvlist_value);
			(void) printf("%*s%s:\n", indent, "",
			    nvpair_name(elem));
			dump_nvlist(nvlist_value, indent + 4);
			break;

		case DATA_TYPE_NVLIST_ARRAY:
			(void) nvpair_value_nvlist_array(elem,
			    &nvlist_array_value, &count);
			for (i = 0; i < count; i++) {
				(void) printf("%*s%s[%u]:\n", indent, "",
				    nvpair_name(elem), i);
				dump_nvlist(nvlist_array_value[i], indent + 4);
			}
			break;
*/
		default:
			(void) printf( "bad config type %d for %s\n", nvpair_type(elem), nvpair_name(elem));
	}
}

static nvpair_t *
zhack_search_nvlist(nvlist_t *list, int argc, char **argv,nvlist_t **container)
{
	nvpair_t *pair;
	nvlist_t **array;
	int err,num;
	uint_t count;

	argc--;

	if (nvlist_exists(list,argv[0])) {
		pair = fnvlist_lookup_nvpair(list,argv[0]);
		switch (nvpair_type(pair)) {
			case DATA_TYPE_NVLIST:
				return zhack_search_nvlist(fnvpair_value_nvlist(pair),argc,&argv[1],container);
				break;

			case DATA_TYPE_NVLIST_ARRAY:
				err = nvpair_value_nvlist_array(pair,&array,&count);
				if (err==0) {
					num = atoi(argv[1]);
					argc--;
					if ( num<count || num<0 )
						return zhack_search_nvlist(array[num],argc,&argv[2],container);
					else {
						printf("array index Incorrect %d not in 0-%d\n",num,count);
					}
				}
				else {
					printf("Error looking up array: %d\n",err);
					return NULL;
				}
				break;

			default:
				*container = list;
				return pair;
		}
	}
	return NULL;
}

static int
zhack_show_label_value(int argc, char **argv)
{

	const char *cfg_keys[] = { ZPOOL_CONFIG_VERSION,
	    ZPOOL_CONFIG_POOL_STATE, ZPOOL_CONFIG_GUID };
	vdev_label_t labels[VDEV_LABELS] = {{{0}}};
	struct stat st;
	int fd;

	abd_init();

  //remove show argument
	argc -= 1;
	argv += 1;

	if (argc < 1) {
		(void) fprintf(stderr, "error: missing device\n");
		usage();
	}

	if ((fd = open(argv[argc-1], O_RDWR)) == -1)
		fatal(NULL, FTAG, "cannot open '%s': %s", argv[0],
		    strerror(errno));

	if (stat(argv[argc-1], &st) != 0)
		fatal(NULL, FTAG, "cannot stat '%s': %s", argv[0],
		    strerror(errno));

	for (int l = 0; l < VDEV_LABELS; l++) {
		uint64_t label_offset;
		nvlist_t *cfg,*nvlist;
		nvpair_t *pair;
		uint64_t val;
		ssize_t err;

		vdev_label_t *vl = &labels[l];

		label_offset = vdev_label_offset(st.st_size, l, 0);
		err = pread64(fd, vl, sizeof (vdev_label_t), label_offset);
		if (err == -1) {
			(void) fprintf(stderr, "error: cannot read "
			    "label %d: %s\n", l, strerror(errno));
			continue;
		} else if (err != sizeof (vdev_label_t)) {
			(void) fprintf(stderr, "error: bad label %d read size "
			    "\n", l);
			continue;
		}

		err = nvlist_unpack(vl->vl_vdev_phys.vp_nvlist,
		    VDEV_PHYS_SIZE - sizeof (zio_eck_t), &cfg, 0);
		if (err) {
			(void) fprintf(stderr, "error: cannot unpack nvlist "
			    "label %d\n", l);
			continue;
		}

		for (int i = 0; i < ARRAY_SIZE(cfg_keys); i++) {
			err = nvlist_lookup_uint64(cfg, cfg_keys[i], &val);
			if (err) {
				(void) fprintf(stderr, "error: label %d: "
				    "cannot find nvlist key %s\n",
				    l, cfg_keys[i]);
				continue;
			}
		}

		printf("Label: %d\n",l);

		pair = zhack_search_nvlist(cfg,argc-1,argv,&nvlist);
		if (pair != NULL ) {
			zhack_print_nvpair(pair,2);
		}
		else
			printf("Error looking up specified value\n");
	}
	close(fd);

	abd_fini();

	return (0);
}

static int
zhack_set_label_value(int argc, char **argv)
{
	zio_checksum_info_t *ci = &zio_checksum_table[ZIO_CHECKSUM_LABEL];
	const char *cfg_keys[] = { ZPOOL_CONFIG_VERSION,
	    ZPOOL_CONFIG_POOL_STATE, ZPOOL_CONFIG_GUID };
	vdev_label_t labels[VDEV_LABELS] = {{{0}}};
	struct stat st;
	int fd;

	abd_init();

  //remove show argument
	argc -= 1;
	argv += 1;

	if (argc < 1) {
		(void) fprintf(stderr, "error: missing device\n");
		usage();
	}

	if ((fd = open(argv[argc-1], O_RDWR)) == -1)
		fatal(NULL, FTAG, "cannot open '%s': %s", argv[0],
		    strerror(errno));

	if (stat(argv[argc-1], &st) != 0)
		fatal(NULL, FTAG, "cannot stat '%s': %s", argv[0],
		    strerror(errno));

	for (int l = 0; l < VDEV_LABELS; l++) {
		uint64_t label_offset, offset;
		zio_cksum_t expected_cksum;
		zio_cksum_t actual_cksum;
		zio_cksum_t verifier;
		zio_eck_t *eck;
		nvlist_t *cfg;
		nvlist_t *nvlist;
		nvpair_t *pair;
		int byteswap;
		uint64_t val;
		ssize_t err;
		size_t size;
		char buf[4096];
		char *cptr;

		vdev_label_t *vl = &labels[l];

		label_offset = vdev_label_offset(st.st_size, l, 0);
		err = pread64(fd, vl, sizeof (vdev_label_t), label_offset);
		if (err == -1) {
			(void) fprintf(stderr, "error: cannot read "
			    "label %d: %s\n", l, strerror(errno));
			continue;
		} else if (err != sizeof (vdev_label_t)) {
			(void) fprintf(stderr, "error: bad label %d read size "
			    "\n", l);
			continue;
		}

		err = nvlist_unpack(vl->vl_vdev_phys.vp_nvlist,
		    VDEV_PHYS_SIZE - sizeof (zio_eck_t), &cfg, 0);
		if (err) {
			(void) fprintf(stderr, "error: cannot unpack nvlist "
			    "label %d\n", l);
			continue;
		}

		for (int i = 0; i < ARRAY_SIZE(cfg_keys); i++) {
			err = nvlist_lookup_uint64(cfg, cfg_keys[i], &val);
			if (err) {
				(void) fprintf(stderr, "error: label %d: "
				    "cannot find nvlist key %s\n",
				    l, cfg_keys[i]);
				continue;
			}
		}

		printf("\nLabel: %d\n",l);

		pair = zhack_search_nvlist(cfg,argc-1,argv,&nvlist);
		if (pair != NULL ) {
			zhack_print_nvpair(pair,2);
			strcpy(buf,nvpair_name(pair));
			//remove old value
			nvlist_remove_nvpair(nvlist,pair);
			switch (nvpair_type(pair)) {
				case DATA_TYPE_UINT64:
					val = strtoul(argv[argc-2],NULL,10);
					fnvlist_add_uint64(nvlist,buf,val);
					break;

				case DATA_TYPE_STRING:
					fnvlist_add_string(nvlist,buf,argv[argc-2]);
					break;

				default:
					printf("Unsupported type given");
					return -1;
			}

			cptr = vl->vl_vdev_phys.vp_nvlist;
			size = sizeof (vl->vl_vdev_phys.vp_nvlist);
			err = nvlist_pack(cfg, &cptr, &size, NV_ENCODE_NATIVE, KM_SLEEP);
			if (err == 0) {
				printf("Sizes %zu %zu\n",size,sizeof(vl->vl_vdev_phys.vp_nvlist));
			}
			else {
				printf("Error code: %ld\n",err);
				return -1;
			}
		}
		else {
			printf("Error looking up value\n");
			return -1;
		}

		// Do the checkum now, this is a direct copy of the checksum function above.
		void *data = (char *)vl + offsetof(vdev_label_t, vl_vdev_phys);
		eck = (zio_eck_t *)((char *)(data) + VDEV_PHYS_SIZE) - 1;

		offset = label_offset + offsetof(vdev_label_t, vl_vdev_phys);
		ZIO_SET_CHECKSUM(&verifier, offset, 0, 0, 0);

		byteswap = (eck->zec_magic == BSWAP_64(ZEC_MAGIC));
		if (byteswap)
			byteswap_uint64_array(&verifier, sizeof (zio_cksum_t));

		expected_cksum = eck->zec_cksum;
		eck->zec_cksum = verifier;

		abd_t *abd = abd_get_from_buf(data, VDEV_PHYS_SIZE);
		ci->ci_func[byteswap](abd, VDEV_PHYS_SIZE, NULL, &actual_cksum);
		abd_free(abd);

		if (byteswap)
			byteswap_uint64_array(&expected_cksum,
			    sizeof (zio_cksum_t));

		if (ZIO_CHECKSUM_EQUAL(actual_cksum, expected_cksum))
			continue;

		eck->zec_cksum = actual_cksum;

		err = pwrite64(fd, data, VDEV_PHYS_SIZE, offset);
		if (err == -1) {
			(void) fprintf(stderr, "error: cannot write "
			    "label %d: %s\n", l, strerror(errno));
			continue;
		} else if (err != VDEV_PHYS_SIZE) {
			(void) fprintf(stderr, "error: bad write size "
			    "label %d\n", l);
			continue;
		}
	}
	close(fd);

	abd_fini();

	return (0);
}


static int
zhack_do_label(int argc, char **argv)
{
	char *subcommand;
	int err;

	argc--;
	argv++;
	if (argc == 0) {
		(void) fprintf(stderr,
		    "error: no label operation specified\n");
		usage();
	}

	subcommand = argv[0];
	if (strcmp(subcommand, "repair") == 0) {
		err = zhack_repair_label_cksum(argc, argv);
	}
	else if (strcmp(subcommand, "show") == 0) {
		err = zhack_show_label_value(argc, argv);
	}
	else if (strcmp(subcommand, "set") == 0) {
		err = zhack_set_label_value(argc, argv);
	}
	else {
		(void) fprintf(stderr, "error: unknown subcommand: %s\n",
		    subcommand);
		usage();
	}

	return (err);
}

#define	MAX_NUM_PATHS 1024

int
main(int argc, char **argv)
{
	extern void zfs_prop_init(void);

	char *path[MAX_NUM_PATHS];
	const char *subcommand;
	int rv = 0;
	int c;

	g_importargs.path = path;

	dprintf_setup(&argc, argv);
	zfs_prop_init();

	while ((c = getopt(argc, argv, "+c:d:")) != -1) {
		switch (c) {
		case 'c':
			g_importargs.cachefile = optarg;
			break;
		case 'd':
			assert(g_importargs.paths < MAX_NUM_PATHS);
			g_importargs.path[g_importargs.paths++] = optarg;
			break;
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;
	optind = 1;

	if (argc == 0) {
		(void) fprintf(stderr, "error: no command specified\n");
		usage();
	}

	subcommand = argv[0];

	if (strcmp(subcommand, "feature") == 0) {
		rv = zhack_do_feature(argc, argv);
	} else if (strcmp(subcommand, "label") == 0) {
		return (zhack_do_label(argc, argv));
	} else {
		(void) fprintf(stderr, "error: unknown subcommand: %s\n",
		    subcommand);
		usage();
	}

	if (!g_readonly && spa_export(g_pool, NULL, B_TRUE, B_FALSE) != 0) {
		fatal(NULL, FTAG, "pool export failed; "
		    "changes may not be committed to disk\n");
	}

	kernel_fini();

	return (rv);
}
