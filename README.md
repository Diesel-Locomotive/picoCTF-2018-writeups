# picoCTF 2018 Writeups
## Table of Contents
### Binary Exploitation
* [Cake](#Cake)

## Problems
### Cake
For this problem we are given a binary file and a libc file. The first step to solving this problem is to reverse the binary file and try to get an understanding of what is going on. Upon doing this, we get the following C pseudocode of what's going on:
```C
struct shop {
    size_t money; // offset 0
    size_t customers; // offset 8
    struct cake* cakes[16]; // offset 16
};

struct cake {
    size_t price; // offset 0
    char name[8]; // offset 8
};

void make(struct shop* shop) {
    int i = index of first empty slot in shop->cakes;

    printf("Making the cake");

    shop->cakes[i] = malloc(16);
    if (shop->cakes[i] == NULL) {
        puts("malloc() return null");
        exit(1);
    }

    printf("Made cake %d\nName> ", i);
    fgets_eat(shop->cakes[i]->name, 8, stdin);

    printf("Price> ");
    shop->cakes[i]->price = get();
}

void inspect(struct shop* shop) {
    printf("Which one?\n> ");
    size_t i = get();
    if (i <= 15 && shop->cakes[i] != NULL) {
        printf("%s is being sold for $%lu\n",
                shop->cakes[i]->name,
                shop->cakes[i]->price);
    } else {
        printf("You didn' make cake %lu yet.\n", i);
    }
}

void serve(struct shop* shop) {
    printf("This customer looks...\n");
    size_t i = get();
    if (i <= 15 && shop->cakes[i] != NULL) {
        printf("The customer looks really happy with %s",
                shop->cakes[i]->name);
        shop->money += shop->cakes[i]->price;
        free(shop->cakes[i]);
        shop->customers--;
    } else {
        printf("Opps!\n");
    }
}

void wait() {
    printf("Twiddling thumbs");
    spin();
    putchar('\n');
}

size_t get() { // stack protection enabled
    size_t a = 0;
    scanf("%ul", &a);
    eat_line();
    return a;
}

void main() {
    srand(0x2df);
    while (true) {
        randomly choose whether to increment shop->customers;
        process_commad();
    }
}
```
