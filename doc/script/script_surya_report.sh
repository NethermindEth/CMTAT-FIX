#/bin/bash
cd '../../'
DIR=$(pwd)
DIR_OUT=${DIR}/doc/surya/surya_report
mkdir -p "$DIR_OUT"
cd './src'
SRC_DIR=$(pwd)
for i in $(find "$SRC_DIR" -type f -name "*.sol");
do
    filename=${i##*/}
    ext=${i##*.}
    if [[ $ext == 'sol' ]]; then
        out="${DIR}/doc/surya/surya_report/surya_report_$filename.md"
        npx surya mdreport "$out" "$i";
        # Use relative paths in the report (strip repo root)
        sed "s|${DIR}/||g" "$out" > "$out.tmp" && mv "$out.tmp" "$out"
    fi
done;