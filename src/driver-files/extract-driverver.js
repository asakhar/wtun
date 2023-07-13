/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

while (!WScript.StdIn.AtEndOfStream) {
	var line = WScript.StdIn.ReadLine();
	if (line.substr(0, 12) != "DriverVer = ")
		continue;
	var val = line.substr(12).split(",");
	var date = val[0].split("/");
	var ver = val[1].split(".");
	var time = Date.UTC(date[2], date[0] - 1, date[1]).toString()
	WScript.Echo("use winapi::shared::{minwindef::{DWORD, FILETIME},ntdef::DWORDLONG};")
	WScript.Echo("pub const WINTUN_INF_FILETIME: FILETIME = FILETIME { dwLowDateTime: ((" + time + "0000u64 + 116444736000000000u64) & 0xffffffff) as DWORD, dwHighDateTime: ((" + time + "0000u64 + 116444736000000000u64) >> 32) as DWORD };")
	WScript.Echo("pub const WINTUN_INF_VERSION: DWORDLONG = (" + ver[0] + "u64 << 48) | (" + ver[1] + "u64 << 32) | (" + ver[2] + "u64 << 16) | (" + ver[3] + "u64 << 0);")
	break;
}
