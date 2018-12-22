#include <stdio.h>
#include <fstream>
#include <string>
#include <streambuf>

struct option_map {
    const char* from;
    const char* to;
} g_table[] = {
    {"/nologo", NULL},
    {"/TP", NULL},
    {"/TP", NULL},
    {"/DWIN32", NULL},
    {"/D_WINDOWS", NULL},
    {"/W3", NULL},
    {"/GR", NULL},
    {"/EHsc", NULL},
    {"/MD", NULL},
    {"/MDd", NULL},
    {"/DNDEBUG", "-DNDEBUG"},
    {"/Zi", "-g"},
    {"/Ob0", NULL},
    {"/Ob1", NULL},
    {"/Ob2", NULL},
    {"/Od", NULL},
    {"/O2", "-O2"},
    {"/RTC1", NULL},
    {"/FS", NULL},
    {"-std:c++11", "-std=c++11"},
    {"-std:c++14", "-std=c++14"},
    {"-std:c++17", "-std=c++17"}
};

const size_t g_table_size = sizeof(g_table)/sizeof(g_table[0]);

std::string requote_defines(const std::string& s)
{
    if (s.size() > 2 && s[0] == '-' && s[1] == 'D') {
        size_t i = 2;
        while(i < s.size() && s[i] != '=')
            ++i;
        if (i >= s.size())
            return s;
        ++i;
        std::string qs = s.substr(0, i);
        while (i < s.size())
        {
            if (s[i] == '"') {
                qs.push_back('\\');
            }
            qs.push_back(s[i]);
            ++i;
        }
        return qs;
    }
    return s;
}

int main(int argc, char** argv)
{
    /*printf("original-call: %s", argv[0]);
    for (int i=0; i < argc; ++i) {
        printf("%s ", argv[i]);
    }
    printf("\n");*/
   

    std::string cmd = "clang";
    bool debug = false;
    for (int i=1; i < argc; ++i)
    {
        std::string a = argv[i];
        bool match = false;
        for(size_t j=0; j < g_table_size; ++j) {
            if (a == g_table[j].from) {
                match = true;
                if (g_table[j].to) {
                    cmd += " ";
                    if (a == "/O2" && debug)
                        cmd += "-Og";
                    else
                        cmd += g_table[j].to;
                } 
                if (a == "/Zi")
                    debug = true;
            }
        }
        if (!match)
        {
            cmd += " " + requote_defines(a);
        }
    }

    //printf("transformed-call: %s\n", cmd.c_str());
    return system(cmd.c_str());
}
