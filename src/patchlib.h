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

/* these are the main exported functions */
int patch_raw(int8_t *file_name, uint32_t offset, void *bytes, SIZE_T count);
int patch_load(int8_t *target, void *addr, void *bytes, SIZE_T count);
int patch_open(int8_t *name, void *addr, void *bytes, SIZE_T count);
int patch_raw_replace(int8_t *file_name, uint8_t *s, uint8_t *r, SIZE_T s_sz, SIZE_T r_sz, int global);

/* internal functions */
int SetPrivilege(LPCTSTR lpszPrivilege);
int pid2tid(int PID);
int pname2pid(int8_t *name);
int arraycmp(uint8_t *a1, uint8_t *a2, SIZE_T sz);

#endif /* !H_PATCHLIB */
