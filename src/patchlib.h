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
int patch_raw(int8_t *fileName, uint32_t offset, uint8_t *bytes, int count);
int patch_load(char *target, void *addr, void *bytes, int count);
int patch_open(int8_t *name, void *addr, void *bytes, int count);

/* internal functions */
int SetPrivilege(LPCTSTR lpszPrivilege);
int get_TID(int PID);
int get_PID(int8_t *name);

#endif /* !H_PATCHLIB */

