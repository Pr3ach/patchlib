/*
 * This file is part of patchlib.
 * Copyright (C) 2015, Preacher
 * All rights reserved.
 *
 * patchlib is a free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * patchlib is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with patchlib.  If not, see <http://www.gnu.org/licenses/>.
 */

#if !defined(H_PATCHLIB)
#define H_PATCHLIB

#define VERSION "1.0"

#define MAX(a, b) (a > b ? a : b)

/* these are the main exported functions */
int patch_raw(int8_t *file_name, long int offset, void *patch, SIZE_T patch_sz);
int patch_load(int8_t *path, void *addr, void *patch, SIZE_T patch_sz);
int patch_open(int8_t *pname, void *addr, void *patch, SIZE_T patch_sz);
unsigned long int patch_raw_replace(int8_t *file_name, uint8_t *s, uint8_t *r, SIZE_T s_sz, SIZE_T r_sz, int global);
unsigned long int patch_load_replace(int8_t *path, uint8_t *s, uint8_t *r, SIZE_T s_sz, SIZE_T r_sz, int global);
unsigned long int patch_open_replace(int8_t *pname, uint8_t *s, uint8_t *r, SIZE_T s_sz, SIZE_T r_sz, int global);
int patch_backup(int8_t *src, int8_t *dest);

/* internal stuff */
typedef struct {
	unsigned long long int base_addr;
	unsigned long int entry_point; /* rva */
	unsigned long int image_sz;
} process_info_t;

int set_privilege(const char *privilege);
int pid2tid(int pid);
int pname2pid(int8_t *pname);
int arraycmp(uint8_t *a1, uint8_t *a2, SIZE_T sz);
int get_process_info(HANDLE process, process_info_t *pinfo);
SIZE_T get_file_size(FILE *fd);

#endif /* !H_PATCHLIB */
