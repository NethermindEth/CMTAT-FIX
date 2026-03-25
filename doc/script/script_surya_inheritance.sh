#/bin/bash
cd '../../'
DIR=$(pwd)
DIR_OUT=${DIR}/doc/surya/surya_inheritance
mkdir -p "$DIR_OUT"
cd './src'
SRC_DIR=$(pwd)
for i in $(find "$SRC_DIR" -type f -name "*.sol");
do
    filename=${i##*/}
    ext=${i##*.}
    if [[ $ext == 'sol' ]]; then
        npx surya inheritance "$i" | dot -Tpng > "${DIR}/doc/surya/surya_inheritance/surya_inheritance_$filename.png";
    fi
done;