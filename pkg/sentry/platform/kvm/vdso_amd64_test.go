// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build amd64
// +build amd64

package kvm

import (
	"slices"
	"testing"
)

const testELFMachineAMD64 = 62 // EM_X86_64

// amd64TestSiteOffsets are the .text offsets of the counter read sites that
// amd64TestSites emits, in the order they are recorded in .altinstructions.
var amd64TestSiteOffsets = []int{128, 134, 140}

// amd64TestSites populates .text of a makeTestVDSOELF image with three
// counter read sites and one unanchored decoy, and returns
// amd64TestSiteOffsets.
//
//	128: rdtscp; xchg %ax, %ax (0f 01 f9 66 90)
//	134: lfence; rdtsc         (0f ae e8 0f 31)
//	140: rdtsc; nopl (%rax)    (0f 31 0f 1f 00)
//	146: rdtsc; nopl (%rax)    (0f 31 0f 1f 00), not an alternatives site
func amd64TestSites(buf []byte) []int {
	copy(buf[128:133], []byte{0x0f, 0x01, 0xf9, 0x66, 0x90})
	buf[133] = 0x90
	copy(buf[134:139], []byte{0x0f, 0xae, 0xe8, 0x0f, 0x31})
	buf[139] = 0x90
	copy(buf[140:145], []byte{0x0f, 0x31, 0x0f, 0x1f, 0x00})
	buf[145] = 0x90
	copy(buf[146:151], []byte{0x0f, 0x31, 0x0f, 0x1f, 0x00})
	buf[151] = 0xc3
	return amd64TestSiteOffsets
}

func TestPatchVDSOTSCOffsetAMD64(t *testing.T) {
	const testOffset = uint64(0x123456789abcdef0)
	const totalStubsLen = amd64RDTSCPStubLen + 2*amd64LFenceRDTSCStubLen

	for _, tc := range []struct {
		name           string
		altSize        int
		wantStubOffset int
	}{
		// With only room for the entries, the stubs go to the zero tail.
		{"ZeroTail", 3 * testVDSOAltEntryLen, testVDSOTailStubOffset(totalStubsLen)},
		// With a large enough .altinstructions, the stubs overwrite it.
		{"DeadSection", 128, testVDSOAltOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := makeTestVDSOELF(testELFMachineAMD64, testPFRX, tc.altSize, amd64TestSiteOffsets)
			sites := amd64TestSites(buf)
			before := append([]byte(nil), buf...)

			patch, err := patchVDSOTSCOffsetAMD64(buf, testOffset)
			if err != nil {
				t.Fatalf("patchVDSOTSCOffsetAMD64 failed: %v", err)
			}
			if !slices.Equal(patch.sites, sites) {
				t.Errorf("patched sites = %v, want %v", patch.sites, sites)
			}
			checkVDSOPatchFootprint(t, before, buf, patch, tc.wantStubOffset)
		})
	}

	t.Run("NoAnchoredSite", func(t *testing.T) {
		buf := makeTestVDSOELF(testELFMachineAMD64, testPFRX, 8, []int{160})
		copy(buf[128:133], []byte{0x0f, 0x31, 0x0f, 0x1f, 0x00})
		if _, err := patchVDSOTSCOffsetAMD64(buf, testOffset); err == nil {
			t.Errorf("expected error when the only rdtsc site is not an alternatives site, got nil")
		}
	})
}

// hostVDSO returns a copy of the host [vdso] image, or nil if the host has no
// [vdso] mapping.
func hostVDSO(t *testing.T) []byte {
	t.Helper()
	var vdso []byte
	if err := applyVirtualRegions(func(vr virtualRegion) bool {
		if vr.filename != "[vdso]" {
			return false
		}
		vdso = append([]byte(nil), sliceFromAddr(vr.virtual, vr.length)...)
		return true
	}); err != nil {
		t.Fatalf("error scanning /proc/self/maps: %v", err)
	}
	return vdso
}

// TestPatchHostVDSOAMD64 patches a copy of the host's own [vdso] and checks
// that the patcher's assumptions hold for the running kernel.
func TestPatchHostVDSOAMD64(t *testing.T) {
	before := hostVDSO(t)
	if before == nil {
		t.Skip("no [vdso] mapping")
	}
	after := append([]byte(nil), before...)

	const testOffset = uint64(0x123456789abcdef0)
	patch, err := patchVDSOTSCOffsetAMD64(after, testOffset)
	if err != nil {
		t.Fatalf("patchVDSOTSCOffsetAMD64 on the host [vdso] failed: %v", err)
	}
	if len(patch.sites) == 0 {
		t.Fatalf("no counter read sites were patched in the host [vdso]")
	}
	checkVDSOPatchFootprint(t, before, after, patch, patch.stubOffset)
}
