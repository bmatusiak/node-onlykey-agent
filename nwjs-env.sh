export npm_config_target=0.60.0
# Setup build architecture, ia32 or x64
export npm_config_arch=x64
export npm_config_target_arch=x64
# Setup env for modules built with node-pre-gyp
export npm_config_runtime=node-webkit
export npm_config_build_from_source=true
# Setup nw-gyp as node-gyp
export npm_config_node_gyp=$(which nw-gyp)




#ubuntu fixes
# sudo apt-get install libudev-dev libusb-1.0-0-dev
# sudo ln -sf python2 /usr/bin/python