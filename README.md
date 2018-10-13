# picoCTF 2018 Writeups
## Table of Contents
### Binary Exploitation
* [Cake](#Cake)

## Problems
### Cake
##### Understanding the problem
For this problem we are given a binary file and a libc file. The first step to solving this problem is to reverse the binary file and try to get an understanding of what is going on. Upon doing this, we get the following C pseudocode of what's going on:

<details><summary>Cake Source Pseudocode</summary>

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

</details>

The first thing we notice is a use-after-free. In the `serve` method

```C
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
```

we see that the cake we serve is freed but we still have access to it in the cakes array stored in our shop struct. How can we exploit this? Well, having just come out of doing contacts, it makes sense to try and utilize a double free in some sort of manner. Let's see what we have to work with.

##### Leaking libc
Thankfully the problem gives us an inspect cake functionality, and this clearly motivates us to leak something: namely libc so that we can defeat ASLR. Trying what we did in `contacts` doesn't work: If we create two cakes, free the first, then inspect the first, we don't get anything interesting. This is because the cakes are being allocated fastbin chunks, so simply inspecting the freed fastbin chunk won't help us leak anything (in `contacts` we had the ability to inspect a freed smallbin). In fact, looking at the `make` method, cakes only malloc 16 bytes of data making overwriting by tricking malloc a little difficult.
This is where we get creative. Notice that each action we take has a chance of incrementing the number of customers we have. Moreover, looking at the store pointer (which has constant location in memory) we see that the structure is such that the total money made is stored in the first qword and the total customers waiting is stored in the second qword, and that the following memory stores all our cake pointers. This means that provided we wait for the appropriate amount of customers, we can fake a valid fastbin chunk header at the store address, and use a double free to trick malloc into letting us overwrite the first two cake pointer.
