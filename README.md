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
Thankfully the problem gives us an inspect cake functionality, and this clearly motivates us to leak something: namely libc so that we can defeat ASLR. Trying what we did in `contacts` doesn't work: If we create two cakes, free the first, then inspect the first, we don't get anything interesting. This is because the cakes are being allocated fastbin chunks, so simply inspecting the freed fastbin chunk won't help us leak anything (in `contacts` we had the ability to inspect a freed smallbin). In fact, looking at the `make` method, cakes only malloc 16 bytes of data which restricts a lot of what we were able to do in `contacts`.

This is where we get creative. Notice that each action we take has a chance of incrementing the number of customers we have. Moreover, looking at the store pointer (which has constant location in memory) we see that the structure is such that the total money made is stored in the first qword and the total customers waiting is stored in the second qword, and that the following memory stores all our cake pointers.
```
0x6030e0 <shop>:	0x0000000000000001	0x0000000000000002
0x6030f0 <shop+16>:	0x0000000000604420	0x0000000000604440
0x603100 <shop+32>:	0x0000000000000000	0x0000000000000000
0x603110 <shop+48>:	0x0000000000000000	0x0000000000000000
0x603120 <shop+64>:	0x0000000000000000	0x0000000000000000
0x603130 <shop+80>:	0x0000000000000000	0x0000000000000000
0x603140 <shop+96>:	0x0000000000000000	0x0000000000000000
0x603150 <shop+112>:	0x0000000000000000	0x0000000000000000
0x603160 <shop+128>:	0x0000000000000000	0x0000000000000000
```
(In the above memory, we see the shop data starts at `0x6030e0`, and that in this particular example we have sold $1 in total, we have two customers, and we have created 2 cakes). Notice that at the shop pointer, we can construct a fake fastbin chunk header provided we wait for the appropriate amount of customers. Since cakes malloc 16 bytes of data, it will be looking for a size of `0x20` in the header, meaning we must wait for 32 customers. What's any good about getting malloc to return shop's pointer? Well, we can overwrite, for example, the first cake's pointer to some GOT entry and then inspect said cake to leak libc. Here's what this sequence of events looks like:
```
create cake 0 -> create cake 1 -> serve cake 0 -> serve cake 1 -> serve cake 0
```
This is our double free, and it makes the fastbin list look like `address(cake 0) -> address(cake 1) -> address(cake 0)`. When we make a new cake, it will first get the address of cake 0 returned by malloc. Since price is the first thing written in the cake struct, we will use price to write a custom FD pointer for when malloc later returns this location in memory again. This looks like `make cake (price = 0x6030e0)` which makes the fastbin list look like `address(cake 1) -> address(cake 0) -> 0x6030e0`. Boom, now we just create two more cakes and the next cake we create will begin writing it's data at `0x6030e0 + 0x10`. We choose to leak the GOT entry for stdout, which happens to be at `0x6030c0`. We also choose to use the name field to overwrite cake 1's pointer with the GOT entry, and use the price field to overwrite cake 0's pointer to `0x6030e0` for reasons that will be explored later. The sequence of actions discussed in the paragraph are thus
```
make cake (price = 0x6030e0) -> make cake -> make cake -> make cake (price = 0x6030e0, name = p64(0x6030c0))
```
(here `p64` is a function that packs the address into a string). Finally calling inspect on cake 1 outputs stdout's GOT entry as the price.
