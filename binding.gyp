{
    "targets": [
        {
            "target_name": "wireguard_bridge",
            "sources": [
                "addon/binding.cc",
                "addon/wgEmbed/wireguard.c",
		"addon/createInterface.cc"
            ],
            "include_dirs" : [
                "<!(node -p \"require('node-addon-api').include_dir\")",
            ],

            # enable C++ exceptions
            'cflags': [ '-fno-exceptions', '-fpermissive' ],

            'xcode_settings': {
                'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
                'CLANG_CXX_LIBRARY': 'libc++',
                'MACOSX_DEPLOYMENT_TARGET': '10.7',
            },
            'msvs_settings': {
                'VCCLCompilerTool': { 'ExceptionHandling': 1 },
            },
        }
    ],
}
