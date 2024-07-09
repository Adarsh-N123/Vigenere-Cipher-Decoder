//CODING THEORY AND CRYPTOGRAPHY ASSIGNMENT VIGENERE CIPHER DECRYPTION
//NAME : NIDAMANURI SAI ADARSH
//ROLL NO: 2103123
//NAME :BABUJI PALIKA POWTHRA
//ROLL NO: 2103124

#include<stdio.h>
#include <stdlib.h>
#include<stdbool.h>
#include<string.h>
#include<math.h>
#include<ctype.h>
#define MAX_PAR_SIZE 100000
#define ALPHABET_SIZE 26
#define MAX_KEY_LENG 100

double ENGLISH_FREQ[ALPHABET_SIZE] = {
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074 
};
double cosine_similarity(double *vec1, double *vec2, int size) {
    double dot_product = 0.0;
    double magnitude_vec1 = 0.0;
    double magnitude_vec2 = 0.0;
    for (int i = 0; i < size; i++) {
        dot_product += vec1[i] * vec2[i];
        magnitude_vec1 += vec1[i] * vec1[i];
        magnitude_vec2 += vec2[i] * vec2[i];
    }
    magnitude_vec1 = sqrt(magnitude_vec1);
    magnitude_vec2 = sqrt(magnitude_vec2);
    if (magnitude_vec1 == 0 || magnitude_vec2 == 0) {
        return 0.0; 
    }
    return dot_product / (magnitude_vec1 * magnitude_vec2);
}

char* read_file(char* filename) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("ErRoR oPeNiNg FiLe");
        return NULL;
    }
    const int MaxLength = 30000;
    char* message = (char*)malloc(MaxLength * sizeof(char));
    if (message == NULL) {
        printf("Memory Allocation Failed");
        fclose(fp);
        return NULL;
    }

    message[0] = '\0'; 
    char line[MaxLength]; 
    while (fgets(line, MaxLength, fp) != NULL) {
        strcat(message, line);
    }
    fclose(fp);
    return message;
}

int compare(const void* num1,const void* num2){
    double a = *(double*) num1;  
    double b = *(double*) num2; 
    if (a>b){return 1;}else if (a<b){return -1;}else{return 0;} 
}
double euclidean_distance(double *vector1, double *vector2, int dimension) {
    double sum = 0.0;
    for (int i = 0; i < dimension; i++) {
        double diff = vector1[i] - vector2[i];
        sum += diff * diff;
    }
    return sqrt(sum);
}

int frequency_analysis_key_length(char* message, int min_key_length, int max_key_length) {
    char charactersequence[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    double match = 0;
    for (int i=0;i<26;i++){
        match+=(ENGLISH_FREQ[i]*ENGLISH_FREQ[i]);
    }
    double maxans = -1;
    int maxanskey = -1;
    for (int t = min_key_length; t <= max_key_length; t++) {
        for (int shift=0;shift<26;shift++){
        double frequencies[26] = {0};
        double sumo = 0;
        int valid = 0;
        
        for (int i = 0; i < strlen(message); i++) {
            if (isalpha(message[i]) && isupper(message[i])) {
                if (valid % t == 0) {
                    int temp = ((message[i] - 'A')-shift)%26;
                    if (temp<0){temp+=26;}
                    frequencies[temp]+=1;
                    sumo+=1;
                }
                valid++;
            }
        }
        
        double ans = 0;
        for (int i = 0; i < 26; i++) {
            frequencies[i] /= sumo;
            ans += frequencies[i]*frequencies[i];
        }
        double sim = cosine_similarity(ENGLISH_FREQ,frequencies,26);
        if (sim>=maxans){
            maxans = sim;
            maxanskey = t;

        }
        }
    }
    
    return maxanskey;
}
int frequency_analysis_key_length1(char* message, int min_key_length, int max_key_length) {
    double match = 0;
    for (int i=0;i<26;i++){
        match+=(ENGLISH_FREQ[i]*ENGLISH_FREQ[i]);
    }
    double maxans = -1;
    int maxanskey = -1;
    double original_rel_freq = 0.0671;
    char charactersequence[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char finalwithoutpunctuation[strlen(message)];
    int validcount = 0;
    for (int j=0;j<strlen(message);j++){
        if (strchr(charactersequence, message[j]) != NULL){
            finalwithoutpunctuation[validcount] = message[j];
            validcount++;
        }
    }
    for (int t = min_key_length; t <= max_key_length; t++) {
        double storetemp[t][26];
        double countarr[t];
        for (int i=0;i<t;i++){
            countarr[i] = 0.0;
            for (int j=0;j<26;j++){
                storetemp[i][j] = 0.0;
            }
        }
        for (int j=0;j<validcount;j++){
            int temp = j%t;
            int temp1 = finalwithoutpunctuation[j]-'A';
            storetemp[temp][temp1]+=1;
            countarr[temp]+=1;
        }
        double sumo = 0;
        for (int i=0;i<t;i++){
            for (int j=0;j<26;j++){
                storetemp[i][j]/=countarr[i];
                sumo+=(storetemp[i][j]*storetemp[i][j]);
            }
        }
        sumo/=t;
        if (sumo>maxans){
            maxans = sumo;
            maxanskey = t;
        }
        
    }
    return maxanskey;
}

int kasiskis_key_length_calculation(char* message, int min_key_length, int max_key_length) {
    int frequencies[26][26][26];
    for (int i = 0; i < 26; i++) {
        for (int j = 0; j < 26; j++) {
            for (int k=0;k<26;k++){
                frequencies[i][j][k] = 0;
            }
        }
    }
    int offset[strlen(message)];
    for (int i=0;i<strlen(message);i++){
        offset[i] = 0;
    }
    int i = 0;
    char charactersequence[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char finalwithoutpunctuation[strlen(message)];
    int validcount = 0;
    for (int j=0;j<strlen(message);j++){
        if (strchr(charactersequence, message[j]) != NULL){
            finalwithoutpunctuation[validcount] = message[j];
            validcount++;
        }
    }
    while (i<validcount && i+2<validcount){
        int first = finalwithoutpunctuation[i]-'A';
        int second = finalwithoutpunctuation[i+1]-'A';
        int third = finalwithoutpunctuation[i+2]-'A';
        frequencies[first][second][third]++;
        i+=1;
    }
    int xmaxfreq = -1;
    int ymaxfreq = -1;
    int zmaxfreq = -1;
    int maxfreq = -1;
    for (int i=0;i<26;i++){
        for (int j=0;j<26;j++){
            for (int k=0;k<26;k++){
            if (frequencies[i][j][k]>maxfreq){
                maxfreq = frequencies[i][j][k];
                xmaxfreq = i;
                ymaxfreq = j;
                zmaxfreq = k;
            }
            }
        }
    }
    int firstoccurance = -1;
    int o = 0;
    while (o<validcount && o+2<validcount){
        int temp1 = finalwithoutpunctuation[o]-'A';
        int temp2 = finalwithoutpunctuation[o+1]-'A';
        int temp3 = finalwithoutpunctuation[o+2]-'A';
        if (xmaxfreq==temp1 && ymaxfreq==temp2 && zmaxfreq==temp3){
            if (firstoccurance==-1){
                firstoccurance=o;
            }else{
                offset[o-firstoccurance]++;
            }
        }
        o++;
    }
    int maxcount = -1;
    int maxkeylength = 0;
    for (int t=min_key_length;t<=max_key_length;t++){
        int count = 0;
        for (int k=0;k<strlen(message);k++){
            if (offset[k]!=0){
                if (k%t==0){
                    count+=offset[k];
                }
            }
        }
        if (count>=maxcount){
            maxcount = count;
            maxkeylength = t;
        }
    }
    return maxkeylength;
}

char break_caesar_cipher(char* column, int size) {
    double max_similarity = -1.0;
    char key = 'a';
    char character_sequence[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    double frequencies[26] = {0};
    int count = 0;
    for (int i = 0; i < size; i++) {
        if (isalpha(column[i])) {
            int index = toupper(column[i]) - 'A';
            frequencies[index]++;
            count++;
        }
    }
    for (int i = 0; i < 26; i++) {
        frequencies[i] /= count;
    }
    for (int j = 0; j < 26; j++) {
        double shifted_frequencies[26] = {0};
        for (int i = 0; i < 26; i++) {
            int shifted_index = (i - j + 26) % 26;
            shifted_frequencies[shifted_index] = frequencies[i];
        }
        double similarity = cosine_similarity(shifted_frequencies, ENGLISH_FREQ, 26);
        if (similarity > max_similarity) {
            max_similarity = similarity;
            key = character_sequence[j];
        }
    }
    return key;
}


int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}




char* break_vigenere_cipher(char* message,int keylength){
    int columnlength = (strlen(message)/keylength)+1;
    int noofcolumns = keylength;
    char* key = (char*)malloc((keylength+1)*sizeof(char));
    int sizesarr[keylength];
    for (int i=0;i<keylength;i++){
        sizesarr[i] = 0;
    }
    char table[noofcolumns][columnlength];
    char charactersequence[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char finalwithoutpunctuation[strlen(message)];
    int validcount = 0;
    for (int j=0;j<strlen(message);j++){
        if (strchr(charactersequence, message[j]) != NULL){
            finalwithoutpunctuation[validcount] = message[j];
            validcount++;
        }
    }
    for (int i=0;i<validcount;i++){
        table[i%keylength][sizesarr[i%keylength]] = finalwithoutpunctuation[i];
        sizesarr[i%keylength]++;
    }
    for (int i=0;i<noofcolumns;i++){
        char keypart = break_caesar_cipher(table[i],sizesarr[i]);
        key[i] = keypart;
    }
    key[keylength] = '\0';
    return key;
}

int indexofcoincidences(char* message,int min_key_length,int max_key_length){
    int storefreq[MAX_KEY_LENG]={0};
    int validcount = 0;
    char charactersequence[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char finalwithoutpunctuation[strlen(message)];
    for (int j=0;j<strlen(message);j++){
        if (strchr(charactersequence, message[j]) != NULL){
            finalwithoutpunctuation[validcount] = message[j];
            validcount++;
        }
    }
    for (int i=min_key_length;i<=max_key_length;i++){
        int start = 0;
        int end = start+i;
        int count = 0;
        while (end<validcount){
            if (isupper(finalwithoutpunctuation[i]) && isalpha(finalwithoutpunctuation[i])){
                if (finalwithoutpunctuation[start]==finalwithoutpunctuation[end]){count++;}
                start++;
                end++;
            }
        }
        storefreq[i] = count;
    }
    int anskeylength = 0;
    int maxnum = -1e9;
    int maxnumidx = -1;
    int secondmaxnum = -1e9;
    int secondmaxnumidx = -1;
    for (int i=min_key_length;i<=max_key_length;i++){
        if (storefreq[i]>maxnum){
            secondmaxnum = maxnum;
            secondmaxnumidx = maxnumidx;
            maxnum = storefreq[i];
            maxnumidx = i;

        }
    }
    anskeylength = maxnumidx;

    return anskeylength;
}

char* decode_vigenere_cipher(char* message, char* key) {
    int keylength = strlen(key);
    int messagelength = strlen(message);
    char* decoded_message = (char*)malloc((messagelength + 1) * sizeof(char)); 
    if (decoded_message == NULL) {
        printf("MeMoRy AlLoCaTiOn FaIlEd");
        return NULL;
    }
    char* character_sequence = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int validcharactercount = -1;
    for (int i = 0; i < messagelength; i++) {
        if (strchr(character_sequence, message[i]) != NULL) {
            validcharactercount++;
            char mainchar = key[validcharactercount % keylength];
            int finalalphabet = ((message[i] - 'A') - (mainchar - 'A')) % 26;
            if (finalalphabet < 0) { 
                finalalphabet += 26;
            }
            decoded_message[i] = character_sequence[finalalphabet];
        }else{
            decoded_message[i] = message[i];
        }
    }
    decoded_message[messagelength] = '\0';
    return decoded_message;
}

int main(){
    printf("==========================================================\n");
    printf("EnTeR tHe FiLeNaMe ThAt CoNtAiNs ThE cIpHeRtExT:");
    char filename[100];
    scanf("%s",filename);
    char* received_message = read_file(filename);
    printf("==========================================================\n");
    printf("==========================================================\n");
    printf("ThE MeSsAgE ReTrIeVeD fRoM tHe FiLe Is:\n");
    printf("==========================================================\n");
    printf("%s\n",received_message);
    printf("==========================================================\n");
    printf("==========================================================\n");
    printf("ThE kEy LeNgTh UsInG kAsIsKiS eXaMiNaTiOn Is FoUnD tO bE:\n");
    printf("==========================================================\n");
    int keylength = kasiskis_key_length_calculation(received_message,3,100);
    printf("%d\n",keylength);
    printf("==========================================================\n");
    printf("==========================================================\n");
    printf("ThE kEy LeNgTh UsInG Frequency eXaMiNaTiOn Is FoUnD tO bE:\n");
    printf("==========================================================\n");
    int keylength2 = frequency_analysis_key_length1(received_message,3,100);
    printf("%d\n",keylength2);
    printf("==========================================================\n");
    printf("==========================================================\n");
    printf("ThE kEy LeNgTh UsInG iNdEx Of CoInCiDeNcEs MeThOd Is FoUnD tO bE a FaCtOr Of:\n");
    printf("==========================================================\n");
    int keylength3 = indexofcoincidences(received_message,3,100);
    printf("%d\n",keylength3);
    printf("==========================================================\n");
    printf("==========================================================\n");
    char* key = break_vigenere_cipher(received_message,keylength);
    char* key2 = break_vigenere_cipher(received_message,keylength2);
    char* key3 = break_vigenere_cipher(received_message,keylength3);
    printf("==========================================================\n");
    printf("BrEaKiNg InTo ViGeNeRe CiPhEr ... FiNdInG kEyS...  DeCoDiNg ViGeNeRe TeXt...\n");
    printf("ThE dEcOdEd TeXt Is:\n");
    printf("==========================================================\n");
    printf("%s",decode_vigenere_cipher(received_message,key3));
    printf("\n==========================================================\n");
    printf("==========================================================\n");
    printf("==========================================================\n");
    printf("FoUnD kEyS...\n");
    printf("==========================================================\n");
    printf("ThE kEy UsInG kAsIsKiS mEtHoD iS(cAn Be WrOnG sOmEtImEs NeEd HuMaN sUpErViSiOn):%s\n",key);
    printf("ThE kEy UsInG fReQuEnCy AnAlYsIs Is:%s\n",key2);
    printf("ThE kEy UsInG cOiNcIdEnCeS mEtHoD iS(CaN aLsO bE a MuLtIpLe Of OrIgInAl KeY):%s\n",key3);
    printf("==========================================================\n");
    printf("==========================================================\n");

}
