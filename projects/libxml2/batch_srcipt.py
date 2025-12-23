import os
from pathlib import Path
import shutil
import json

'''
Append this to build.sh for each harness file.

$CC $CXXFLAGS \
        $SRC/xmlloadcatalogs.c fuzz/fuzz.o \
        -o $OUT/xmlloadcatalogs\
        -I./include $LIB_FUZZING_ENGINE \
        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic
'''

def append_for_batch():

    project_dir = Path(os.getcwd())

    docker_file =  project_dir / 'Dockerfile'
    build_sh: Path = project_dir / 'build.sh'

    all_harnesses: list[tuple[str, str]] = []
    for file in project_dir.iterdir():   
        if file.is_file():
            continue
        
        # get harness file
        harness_name = file.name
        fuzzer_info = file / 'fuzzer_info.json'
        if not fuzzer_info.exists():
            continue
        with open(fuzzer_info, 'r') as f:
            json_data = json.load(f)
            fuzzer_name = json_data.get('fuzzer_name', '')

        assert fuzzer_name != '', f'Fuzzer name not found in {fuzzer_info}'

        all_harnesses.append((harness_name, fuzzer_name))


    # create a dir for harness files

    harness_dir = project_dir / 'all_harnesses'
    harness_dir.mkdir(exist_ok=True)

    for harness, _ in all_harnesses:
        src_file = project_dir / harness / 'harness.txt'
        dest_file = harness_dir / f'{harness}.c'
        shutil.copy(src_file, dest_file)
    
    with open(docker_file, 'a') as f:
        f.write('\n')
        f.write(f'COPY all_harnesses/*.c $SRC/all_harnesses/\n')
      

    with open(build_sh, 'a') as f:
        for harness, fuzzer_name in all_harnesses:
            f.write('\n')
            f.write('$CC $CXXFLAGS \\\n')
            if fuzzer_name == "lint":
                f.write(f'        $SRC/all_harnesses/{harness}.c fuzz/fuzz.o libxml2/xmllint.o libxml2/shell.o \\\n')
            else:
                f.write(f'        $SRC/all_harnesses/{harness}.c fuzz/fuzz.o \\\n')
            f.write(f'        -o $OUT/{harness}\\\n')
            f.write('        -I./include $LIB_FUZZING_ENGINE \\\n')
            f.write('        ./.libs/libxml2.a -Wl,-Bstatic -lz -Wl,-Bdynamic\n')

if __name__ == '__main__':
    append_for_batch()