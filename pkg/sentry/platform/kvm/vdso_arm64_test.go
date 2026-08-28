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

//go:build arm64
// +build arm64

package kvm

import (
	"encoding/binary"
	"slices"
	"testing"
)

const testELFMachineARM64 = 183 // EM_AARCH64

// arm64TestSites populates .text of a makeTestVDSOELF image with two counter
// read sites and returns their offsets.
//
//	128: isb
//	132: mrs x2, cntvct_el0
//	136: nop
//	140: mrs x0, cntvctss_el0
func arm64TestSites(buf []byte) []int {
	binary.LittleEndian.PutUint32(buf[128:132], 0xd5033fdf) // isb
	binary.LittleEndian.PutUint32(buf[132:136], 0xd53be042) // mrs x2, cntvct_el0 (rt=2)
	binary.LittleEndian.PutUint32(buf[136:140], 0xd503201f) // nop
	binary.LittleEndian.PutUint32(buf[140:144], 0xd53be0c0) // mrs x0, cntvctss_el0 (rt=0)
	return []int{132, 140}
}

func TestPatchVDSOTSCOffsetARM64(t *testing.T) {
	const testOffset = uint64(0x123456789abcdef0)
	const totalStubsLen = arm64LiteralLen + 2*arm64StubLen

	for _, tc := range []struct {
		name           string
		altSize        int
		wantStubOffset int
	}{
		// Without a usable dead section, the stubs go to the zero tail.
		{"ZeroTail", 0, testVDSOTailStubOffset(totalStubsLen)},
		// With a large enough .altinstructions, the stubs overwrite it.
		{"DeadSection", 128, testVDSOAltOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := makeTestVDSOELF(testELFMachineARM64, testPFRX, tc.altSize, nil)
			sites := arm64TestSites(buf)
			before := append([]byte(nil), buf...)

			patch, err := patchVDSOTSCOffsetARM64(buf, testOffset)
			if err != nil {
				t.Fatalf("patchVDSOTSCOffsetARM64 failed: %v", err)
			}
			if !slices.Equal(patch.sites, sites) {
				t.Errorf("patched sites = %v, want %v", patch.sites, sites)
			}
			checkVDSOPatchFootprint(t, before, buf, patch, tc.wantStubOffset)

			litOff := patch.stubOffset
			if lit := binary.LittleEndian.Uint64(buf[litOff : litOff+8]); lit != testOffset {
				t.Fatalf("expected literal %#x at %d, got %#x", testOffset, litOff, lit)
			}
		})
	}

	t.Run("NoSite", func(t *testing.T) {
		buf := makeTestVDSOELF(testELFMachineARM64, testPFRX, 0, nil)
		binary.LittleEndian.PutUint32(buf[128:132], 0xd53be05f) // mrs xzr, cntvct_el0
		if _, err := patchVDSOTSCOffsetARM64(buf, testOffset); err == nil {
			t.Errorf("expected error when the only counter read targets XZR, got nil")
		}
	})
}
