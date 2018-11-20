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
    {"/MDd", NULL},
    {"/Zi", "-g"},
    {"/Ob0", NULL},
    {"/Od", NULL},
    {"/RTC1", NULL},
    {"/FS", NULL}
};

const size_t g_table_size = sizeof(g_table)/sizeof(g_table[0]);
int main(int argc, char** argv)
{
    printf("original-call: %s", argv[0]);
    for (int i=0; i < argc; ++i) {
        printf("%s ", argv[i]);
    }
    printf("\n");
   

    std::string cmd = "clang";
    for (int i=1; i < argc; ++i)
    {
        std::string a = argv[i];
        bool match = false;
        for(size_t j=0; j < g_table_size; ++j) {
            if (a == g_table[j].from) {
                match = true;
                if (g_table[j].to) {
                    cmd += " ";
                    cmd += g_table[j].to;
                } 
            }
        }
        if (!match)
        {
            cmd += " " + a;
        }
    }

    printf("transformed-call: %s\n", cmd.c_str());
    return system(cmd.c_str());
}
