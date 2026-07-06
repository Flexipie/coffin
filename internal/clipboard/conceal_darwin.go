//go:build darwin && cgo

package clipboard

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit
#import <AppKit/AppKit.h>

// coffin_copy_concealed writes text to the general pasteboard together
// with the org.nspasteboard.ConcealedType marker (nspasteboard.org
// convention), so clipboard history managers skip it. Returns 1 on
// success.
static int coffin_copy_concealed(const char *text) {
	@autoreleasepool {
		NSString *s = [NSString stringWithUTF8String:text];
		if (s == nil) {
			return 0;
		}
		NSPasteboard *pb = [NSPasteboard generalPasteboard];
		[pb clearContents];
		[pb declareTypes:@[NSPasteboardTypeString, @"org.nspasteboard.ConcealedType"] owner:nil];
		if (![pb setString:s forType:NSPasteboardTypeString]) {
			return 0;
		}
		[pb setString:@"" forType:@"org.nspasteboard.ConcealedType"];
		return 1;
	}
}

// coffin_pasteboard_types returns the current pasteboard types joined
// by newlines; caller frees. Debug/verification only.
static char *coffin_pasteboard_types(void) {
	@autoreleasepool {
		NSArray *types = [[NSPasteboard generalPasteboard] types];
		return strdup([[types componentsJoinedByString:@"\n"] UTF8String]);
	}
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

const concealSupported = true

// copyConcealed writes text to the macOS pasteboard marked concealed.
func copyConcealed(text string) error {
	cs := C.CString(text)
	defer C.free(unsafe.Pointer(cs))
	if C.coffin_copy_concealed(cs) != 1 {
		return errors.New("coffin: pasteboard write failed")
	}
	return nil
}

// pasteboardTypes lists the pasteboard's current types, one per line.
// Used by the manual verification test.
func pasteboardTypes() string {
	cs := C.coffin_pasteboard_types()
	defer C.free(unsafe.Pointer(cs))
	return C.GoString(cs)
}
