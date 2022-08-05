{
  "targets": [
    {
      "target_name": "wireguard_bridge",
      "cflags": [
        "-fpermissive",
        "-fno-exceptions",
        "-w",
        "-fpermissive",
        "-fPIC",
        "-static"
      ],
      "cflags_cc": [
        "-fpermissive",
        "-fno-exceptions",
        "-w",
        "-fpermissive",
        "-fPIC",
        "-static"
        ],
      "sources": [
        "src/addon/binding.cc",
        "src/addon/wgEmbed/wireguard.c",
      ],
      "include_dirs" : [
        "<!(node -p \"require('node-addon-api').include_dir\")",
        "$(srcdir)/libnl/include/libnl3"
      ],
      "libraries": [
        "$(srcdir)/libnl/lib/libnl-xfrm-3.a",
        "$(srcdir)/libnl/lib/libnl-nf-3.a",
        "$(srcdir)/libnl/lib/libnl-3.a",
        "$(srcdir)/libnl/lib/libnl-idiag-3.a",
        "$(srcdir)/libnl/lib/libnl-route-3.a",
        "$(srcdir)/libnl/lib/libnl-genl-3.a",
      ],
    }
  ],
}
