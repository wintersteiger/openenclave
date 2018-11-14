#include <stdio.h>
#include <fstream>
#include <string>
#include <streambuf>
#include <sstream>
#include <vector>


std::string file_to_string(const char* file)
{
    std::ifstream f(file);
    return std::string((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
}

template<typename Out>
void split(const std::string &s, char delim, Out result) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}

int main(int argc, char** argv)
{
    return 1;
    std::string output = "lib.a";
    std::string files_str = "";
    std::vector<std::string> files;
    bool raw_ar_call = false;

    for(int i=1; i < argc; ++i)
    {
        std::string p = argv[i];

        if (p == "qc") {
            // This is an invocation to ar instead of the msvc linker.
            // Happens when building mbedtls libraries via external projects.
            // The output is the next file.
            ++i;
            p = argv[i++];
            // ignore the .lib extension
            output = p.substr(0, p.size() - 4);
            

            // scan individual files from command line.
            while (i < argc) {
                files.push_back(argv[i]);
                ++i;
            }
            continue;
        }

        if (p.size() > 5 && p.substr(0, 5) == "/out:") {
            // exclude .obj as well
            if (output.substr(output.size()-3, 3) == "lib")
                output = p.substr(5, p.size() - 5 - 4);
            else 
                output = p.substr(5);
         }
        else if(p[0] == '@') {
            files_str = file_to_string(p.substr(1).c_str());
        }
    }

    printf("output = %s\n", output.c_str());
    std::string liboutput = "";

    if (output.substr(output.size() - 2, 2) != ".a")
    {
        std::vector<std::string> output_comps;
        split(output, '\\', std::back_inserter(output_comps));
        
        output_comps.back() = "lib" + output_comps.back();
        liboutput = output_comps[0];
        for (size_t i=1; i < output_comps.size(); ++i) {
            liboutput += "\\" + output_comps[i];
        }
    } else {
        liboutput = output;
    }


    if (files_str != "")
    {
        split(files_str, ' ', std::back_inserter(files));
        //printf("files = %d\n", (int) files.size());       
    }

    int res = 0;
    size_t i = 0;
    while (i < files.size())
    {
        size_t j = i;
        auto tcmd = "ld.lld -o " + liboutput + " ";
        while (j < i + 10000 && j < files.size())
        {
            tcmd += files[j] + " ";        
            ++j;
        }
        printf("executing : %s\n", tcmd.c_str());
        res = system(tcmd.c_str());
        if (res)
            return res;        
        i = j;
        //printf("here : %d\n", j);
    }

    
    // Keep original extension
    if (output != liboutput)
        return system(("copy " + liboutput + " " + output + ".lib").c_str());
    return 0;
}
