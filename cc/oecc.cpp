#include <stdio.h>
#include <fstream>
#include <string>
#include <streambuf>

std::string file_to_string(const char* file)
{
    std::ifstream f(file);
    return std::string((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
}

struct option_map {
    const std::string from;
    const std::string to;
} table[] = {
    {"/nologo", ""},
    {"/TP", ""},
    {"/TP", ""},
    {"/DWIN32", ""},
    {"/D_WINDOWS", ""},
    {"/W3", ""},
    {"/GR", ""},
    {"/EHsc", ""},
    {"/MDd", ""},
    {"/Zi", ""},
    {"/Ob0", ""},
    {"/Od", ""},
    {"/RTC1", ""},
    {"/FS", ""}
};

const size_t table_size = sizeof(table)/sizeof(table[0]);

std::string transform_arguments(const std::string& s)
{
    std::string t = "";
    auto itr = s.begin();
    auto end = s.end();
    while (itr != end)
    {
       if(*itr == '"') {
            auto start = itr++;
            while (itr != end)
            {
                if (*itr == '"')
                {
                    ++itr;
                    t += std::string(start, itr);
                    break;
                }
                ++itr;
            }              
        } 
        else if (*itr == ' ') {
            t += " ";
            ++itr;
            while (itr != end && *itr == ' ')
                ++itr;
        }

        else {
            auto start = itr++;            
            while (true)
            {
                if (itr == end || *itr == ' ' || *itr == '"') {
                    auto p = std::string(start, itr);
                    for (size_t i=0; i < table_size; ++i)
                    {
                        if (p == table[i].from)
                        {
                            t += table[i].to;
                            p = "";
                            break;
                        }                        
                    }

                    if (p.size() > 3 && p[0]=='/' && p[1] == 'F')
                    {
                        if (p[2] == 'o')
                        {
                            t += "-o " + p.substr(3);
                            p = "";
                            break;
                        }
                        else if(p[2] == 'd')
                        {
                            p = "";
                            break;
                        }
                    }
                    if (p != "")
                        t += p;                        
                    break;
                }
                ++itr;
            }
        }
    }


    return t;
}

int main(int argc, char** argv)
{
    printf("orig: ");
    for (int i=0; i < argc; ++i) {
        printf("%s ", argv[i]);
    }
    printf("\n");
    if (argc == 2 && argv[1][0] == '@')
    {
        std::string cmd = file_to_string(argv[1]+1);
        printf("invocation: oecc %s\n", cmd.c_str());
        auto tcmd = "clang -target x86_64-pc-linux -nostdinc -nodefaultlibs -fPIC -I../../include -g " + transform_arguments(cmd);
        printf("invocation-rewritten: %s\n", tcmd.c_str());
        return system(tcmd.c_str());
    } else {
        std::string tcmd = "clang -target x86_64-pc-linux -nostdinc -nodefaultlibs -fPIC -g ";
        for (int i=1; i < argc; ++i) {
            tcmd += argv[i];
            tcmd += " ";
        }
        printf("invocation-rewritten: %s\n", tcmd.c_str());
        return system(tcmd.c_str());
    }   

    return 0;
}