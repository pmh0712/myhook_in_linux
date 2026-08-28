#include <stdio.h>
#include <string.h>

void readline(char *input)
{
    fgets(input, 50, stdin);
    int len = strlen(input);
    input[len-1] = '\0';
}

int main(){
    char password[]="secret123";
    char input[50]="";

    printf("input password: ");
    readline(input);

    if (strcmp(input, password)==0){
        printf("success!\n");
    }
    else{
        printf("fail!\n");
        return 0;
    }

    printf("type this sentence!: This is hook study!!\n");
    while(1)
    {
        printf("input: ");
        readline(input);
        
        if (strcmp(input, "This is hook study!!") == 0){
            printf("well done!!\n");
            break;
        }
    }

    return 0;
}