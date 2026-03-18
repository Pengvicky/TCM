1.安装对应依赖

2.下载openssl（需要openssl-1.1.1n以上）

cd ~

wget https://www.openssl.org/source/openssl-1.1.1n.tar.gz

tar -xzvf openssl-1.1.1n.tar.gz

cd openssl-1.1.1n

./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl \ no-idea no-mdc2 no-rc5 no-ssl3 no-weak-ssl-ciphers \ -Wa,--noexecstack

make

sudo make install

3.编译运行

./bootstrap 

./configure CPPFLAGS="-I/usr/local/ssl/include" LDFLAGS="-L/usr/local/ssl/lib"   --prefix=/usr/local

make

sudo make install

启动 TPM 模拟器（如果尚未运行）

tpm2-simulator &

设置环境变量

export TPM2TOOLS_TCTI="mssim:host=localhost,port=2321"

初始化 TPM

tpm2_startup -c

获取随机数

tpm2_getrandom 8 --hex
