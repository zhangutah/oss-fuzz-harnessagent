// Generate a fuzz driver based the given function signature in CPP language. 
//  You can call the following tools to get more information about the code.
//  Prefer higher-priority tools first; only use view_code when you already know the exact file path and a line number:
//  
//  1) get_symbol_header_tool — Get the header file(s) needed for a symbol. Try an absolute path first (e.g., #include "/path/to/header.h"). If that fails with ".h file not found", try a project-relative path.
//  2) get_symbol_definition_tool — Get the definition of a symbol (the function body or struct/class definition).
//  3) get_symbol_declaration_tool — Get the declaration (prototype/signature) of a symbol.
//  4) get_symbol_references_tool — Get the references/usage of a symbol within the codebase.
//  5) get_struct_related_functions_tool — Get helper functions that operate on a struct/class (e.g., init, destroy, setters/getters).
//  6) view_code — View code around a specific file path and target line. Use this only when the path and line are known; keep context_window small.
//  7) get_file_location_tool - Get the absolute path of a file in the project codebase.
//  8) get_driver_example_tool - Randomly select one harness file in the container and return its content. 
// 
//  Guardrails:
//  - Don't call view_code repeatedly to browse; instead, first retrieve definitions/headers/references to precisely locate what you need.
//  - Avoid requesting huge windows; stay within a small context_window unless specifically needed.
// 
// @ examples of API usage:
// 
// 
// Useful project headers:
// 
// 
// 
// 
// The following function fuzzes
//     int config__get_dir_files(const char * include_dir, char *** files, int * file_count);
// 
// The fuzzer entry point is defined as follows:
// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// Output the full driver code in reply.
// Fuzz driver for:
//   int config__get_dir_files(const char * include_dir, char *** files, int * file_count);
// Fuzzer entry point:
//   extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

// Include the project header that declares config__get_dir_files.
// Try absolute path as suggested by tool output.
extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
}

// Helper: create a temporary directory using mkdtemp. Returns empty string on failure.
static std::string make_temp_dir()
{
    char tmpl[] = "/tmp/fuzzdirXXXXXX";
    char *d = mkdtemp(tmpl);
    if(!d) return std::string();
    return std::string(d);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Basic guard.
    if(!Data || Size == 0) return 0;

    // Create a temporary directory to act as include_dir.
    std::string tmpdir = make_temp_dir();
    if(tmpdir.empty()) return 0;

    std::vector<std::string> created_paths;
    created_paths.reserve(64);

    // Limit number of files created to avoid resource exhaustion.
    size_t max_files = std::min<size_t>(100, Size);

    // Use the input bytes to generate file names and contents.
    for(size_t i = 0; i < max_files; ++i){
        // Determine a small name length using input data.
        size_t idx = i % Size;
        size_t name_len = 1 + (Data[idx] % 20); // between 1 and 20

        std::string name;
        name.reserve(name_len + 6);
        for(size_t j = 0; j < name_len; ++j){
            uint8_t b = Data[(idx + j) % Size];
            char c = 'a' + (b % 26);
            name.push_back(c);
        }

        // Randomly decide whether to append ".conf" (to be picked up by config__get_dir_files)
        // or a different extension.
        if(Data[(idx + 1) % Size] % 2 == 0){
            name += ".conf";
        }else{
            name += ".txt";
        }

        std::string full = tmpdir + "/" + name;

        // Create the file and write a few bytes derived from input.
        FILE *f = fopen(full.c_str(), "wb");
        if(f){
            size_t to_write = std::min<size_t>(16, Size - idx);
            fwrite(Data + idx, 1, to_write, f);
            fclose(f);
            created_paths.push_back(full);
        }
    }

    // Also create a subdirectory and a .conf file inside to exercise readdir filtering.
    {
        std::string subdir = tmpdir + "/subdir";
        if(mkdir(subdir.c_str(), 0700) == 0){
            std::string subconf = subdir + "/inside.conf";
            FILE *f = fopen(subconf.c_str(), "wb");
            if(f){
                fwrite(Data, 1, std::min<size_t>(8, Size), f);
                fclose(f);
                // Note: config__get_dir_files does not recurse into subdirectories, but presence of subdir is useful.
                created_paths.push_back(subconf);
            }
        }
    }

    // Call the target function.
    char **files = nullptr;
    int file_count = 0;

    // The function returns 0 on success, 1 on error (e.g., cannot open dir).
    // We ignore the return value but handle allocated outputs when successful.
    int rc = config__get_dir_files(tmpdir.c_str(), &files, &file_count);

    if(rc == 0 && files != nullptr && file_count > 0){
        // Iterate through returned file list to touch memory and then free it.
        for(int i = 0; i < file_count; ++i){
            if(files[i]){
                // Access the string to potentially trigger any use-after-free or read issues.
                volatile char c = files[i][0];
                (void)c;
                free(files[i]); // allocated by mosquitto_malloc/mosquitto_realloc in original code
            }
        }
        free(files); // free the array allocated by mosquitto_realloc
    }

    // Cleanup created files and directories.
    for(const auto &p : created_paths){
        unlink(p.c_str());
    }

    // Remove the subdir if it exists.
    rmdir((tmpdir + "/subdir").c_str());

    // Remove any remaining entries and the tmpdir itself.
    // Try to remove files we created directly in tmpdir.
    DIR *dh = opendir(tmpdir.c_str());
    if(dh){
        struct dirent *de;
        while((de = readdir(dh)) != nullptr){
            if(strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
            std::string path = tmpdir + "/" + de->d_name;
            unlink(path.c_str());
        }
        closedir(dh);
    }
    rmdir(tmpdir.c_str());

    return 0;
}
