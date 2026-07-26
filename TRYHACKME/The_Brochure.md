# The Brochure Challenge - TryHackMe (OSINT)

I am solving **The Brochure** challenge on **TryHackMe**.  
This is an **OSINT (Open Source Intelligence)** challenge.

The challenge provides an image and the objective is to find hidden clues inside it.

<img width="726" height="934" alt="image" src="https://github.com/user-attachments/assets/5208a45d-f4f8-4a42-b67f-df81a10a0687" />

## Instructions

**Today's Itinerary:**

- Analyze the provided image for embedded clues.
- Apply fundamental OSINT techniques to trace the findings.
- Locate the hidden social media account.
- Submit the flag.

## Investigation

First, I analyzed the provided image by checking:

- Metadata
- Hidden files
- Strings inside the image

However, I did not find anything useful.

After further OSINT investigation, I discovered an Instagram account:



@thebytelotusresort
<img width="852" height="781" alt="image" src="https://github.com/user-attachments/assets/7566b79a-22a0-4686-ac6b-138c1283432e" />






While analyzing the following list of this account, I found only one suspicious account:
@veratheconcierge

<img width="940" height="988" alt="image" src="https://github.com/user-attachments/assets/74422d81-1b16-4101-877b-b3cffbcd102c" />



## Finding the Flag

The account `@veratheconcierge` had three posts containing Base64-encoded parts.


The encoded parts were:

### Part 1



VEhNe1YzckBzX2FD


### Part 2



QzB1bnRfaDRzX2Iz


### Part 3



M25fZjB1bmQhfQ==


I combined all three parts:



VEhNe1YzckBzX2FDQzB1bnRfaDRzX2IzM25fZjB1bmQhfQ==


Then decoded it using:

```bash
echo "VEhNe1YzckBzX2FDQzB1bnRfaDRzX2IzM25fZjB1bmQhfQ==" | base64 -d
```

The decoded output revealed the final flag.
