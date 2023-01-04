## Debugging Kerberos

Kerberos is used in a wide variety of modules and tools but it doesn't always work as you might expect.
Here we're going to go through some methods of debugging issues you might run into whilst using Kerberos in Metasploit.

### Inspecting Tickets

Kerberos makes use of tickets as a means of authentication, so as a pentester you may want to
forge one of these tickets to gain access to something you probably aren't supposed to have access to.
So you use the `modules/auxiliary/admin/kerberos/forge_ticket` module and forge out a new ticket.
You go to use the ticket and... it doesn't work and the error message is super unhelpful, what can you do to debug your ticket?

You can use the `modules/auxiliary/admin/kerberos/inspect_ticket` module!
This module will display the contents of whatever ccache or kirbi file you provide.

For the most basic use of the module all you need is to set `TICKET_PATH` and `run` and the output will be similar to the following:
```
Primary Principal: Administrator@WINDOMAIN.LOCAL
Ccache version: 4
Creds: 1
  Credential[0]:
    Server: cifs/dc.windomain.local@WINDOMAIN.LOCAL
    Client: Administrator@WINDOMAIN.LOCAL
    Ticket etype: 18 (AES256)
    Key: 3436643936633032656264663030393931323461366635653364393932613763
    Ticket Length: 978
    Subkey: false
    Addresses: 0
    Authdatas: 0
    Times:
      Auth time: 2022-11-21 13:52:00 +0000
      Start time: 2022-11-21 13:52:00 +0000
      End time: 2032-11-18 13:52:00 +0000
      Renew Till: 2032-11-18 13:52:00 +0000
    Ticket:
      Ticket Version Number: 5
      Realm: WINDOMAIN.LOCAL
      Server Name: cifs/dc.windomain.local
      Encrypted Ticket Part:
        Ticket etype: 18 (AES256)
        Key Version Number: 2
        Cipher:
          1YrnB+fhzeLEq+4NUcXvoEsSI29+gwCDg3qjYdb0YHhqx23BhZGOK9rIQ99uXeuLHSapJAanCE9g/PyyKDE1kggrEHfy6cxwsP25exmN2w3NXVm7P0PqMVON2RBp2S11eIdF/Zibhrs7JbaaVw0Hv8GpbpHdFI0l6Xx3Jz+y0bqFsFNEsU8nEW35Z3Oo2xpI/xTwNTyG1Bmg+bktSLyI6nEPtJXQKcoJTrNhSBNsZ18HZiUPim9EqSCHUh0VbDeLntryh+lt0TIgwhwipHPWnro+Y81dvX5j8ZeBdgKgnoX3jciU629u/RveQJgyw/vLk1KT0RzTbHSwdRk/xi6ghccvew33TKJ8q3nP/JuSWDzaDE6I6v3KgInSZP+XkCAV5VT//U49MtIVIKARcmtXQwVxztMXKlWjIaxQwl9BN6CuyWZjDcafAssjPWgWIAsesmEWHn3btv1BP0a4gvn5f1b7Fu4Gh6w0ARCryxZkSl+6UhJbcdaRT23WhqN24ECGEl0VIX4fuLs6x0gVtAQ2YsI+HkoQYuI+C28gXzJUCac6rJyFQSTsciwj/jVf18ttw1vfGGKa/BVcqscGZoJPpBiuGPBkIbeAOery0Sjn+0tP0tsPYw1OkpzZ7n/j/YdmTX6UAFZjCLbgvF8hoPyider1gntOiSjlLlEUITLTfe5zqWi4gs47Ly6lvggBWW9Yg0fIaPOHYMvsszMLcJz0+dFXtDVI452LIEatLDvp1aKkwGANWYyRgOMlHR3fD030SOTNEb5oa6WigWZQLlhuDbgrfFaWWAMp7opcNbNKy7Iv17EscL7pW2Ygc38VbmbFtdIfvpQ9niwLr2msjzhB7RPihZXcUAlVygLwykq0JDG4fRmoNXzNydbnYlX9E+KW0fHFjoBitAx1xrp9p5Ajwoyy+wIk0mt/aC4pbfcoRjt4GUF/9DhZnH3HiPn4lM9TLMzpiediEtDZtKgGvAAP2cJZn2gsLRlKAtBZvl+ibe1uDzC9g6rnObAx3c+OSG9rmHzBBCq6D8wW6ZjrQy8njNuriC5rnQxUpVhgGvTOkeTphSIHX+D4SuMd+XZ4zqa3DsrHzIeVWAvrTHCDBzy+DKt2RoQTwYmGT+a0YB0btQtgIfRj2OwDtlP65JUxC+/ANelHg73d0REoYistB5ZMmvk=
```
This is a great place to start, you can verify the `Server`, `Client`, `Realm`, etc. are what you expect.

We can do better than that though. Notice the element of the ticket named `Cipher`,
this is data that has been encrypted and if you know the key (which in the case of forging the ticket you do) 
we can decrypt this and display the ticket in full.

To do that you just need to set either `NTHASH` or `AES_KEY` (depending on which type of key was used, 
you can also see the type of key used in the previous output) and then `run` again to see something like this:

```
Primary Principal: Administrator@WINDOMAIN.LOCAL
Ccache version: 4
Creds: 1
  Credential[0]:
    Server: cifs/dc.windomain.local@WINDOMAIN.LOCAL
    Client: Administrator@WINDOMAIN.LOCAL
    Ticket etype: 18 (AES256)
    Key: 3436643936633032656264663030393931323461366635653364393932613763
    Ticket Length: 978
    Subkey: false
    Addresses: 0
    Authdatas: 0
    Times:
      Auth time: 2022-11-21 13:52:00 +0000
      Start time: 2022-11-21 13:52:00 +0000
      End time: 2032-11-18 13:52:00 +0000
      Renew Till: 2032-11-18 13:52:00 +0000
    Ticket:
      Ticket Version Number: 5
      Realm: WINDOMAIN.LOCAL
      Server Name: cifs/dc.windomain.local
      Encrypted Ticket Part:
        Ticket etype: 18 (AES256)
        Key Version Number: 2
        Decrypted (with key: \x4b\x91\x2b\xe0\x36\x6a\x6f\x37\xf4\xa7\xd5\x71\xbe\xe1\x8b\x11\x73\xd9\x31\x95\xef\x76\xf8\xd1\xe3\xe8\x1e\xf6\x17\x2a\xb3\x26):
          Times:
            Auth time: 2022-11-21 13:52:00 UTC
            Start time: 2022-11-21 13:52:00 UTC
            End time: 2032-11-18 13:52:00 UTC
            Renew Till: 2032-11-18 13:52:00 UTC
          Client Addresses: 0
          Transited: tr_type: 0, Contents: ""
          Client Name: 'Administrator'
          Client Realm: 'WINDOMAIN.LOCAL'
          Ticket etype: 18 (AES256)
          Encryption Key: 3436643936633032656264663030393931323461366635653364393932613763
          Flags: 0x50a00000 (FORWARDABLE, PROXIABLE, RENEWABLE, PRE_AUTHENT)
          PAC:
            Validation Info:
              Logon Time: 2022-11-21 13:52:00 +0000
              Logoff Time: Never Expires (inf)
              Kick Off Time: Never Expires (inf)
              Password Last Set: No Time Set (0)
              Password Can Change: No Time Set (0)
              Password Must Change: Never Expires (inf)
              Logon Count: 0
              Bad Password Count: 0
              User ID: 500
              Primary Group ID: 513
              User Flags: 0
              User Session Key: \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
              User Account Control: 528
              Sub Auth Status: 0
              Last Successful Interactive Logon: No Time Set (0)
              Last Failed Interactive Logon: No Time Set (0)
              Failed Interactive Logon Count: 0
              SID Count: 0
              Resource Group Count: 0
              Group Count: 5
              Group IDs:
                Relative ID: 513, Attributes: 7
                Relative ID: 512, Attributes: 7
                Relative ID: 520, Attributes: 7
                Relative ID: 518, Attributes: 7
                Relative ID: 519, Attributes: 7
              Logon Domain ID: S-1-5-21-3541430928-2051711210-1391384369
              Effective Name: 'Administrator'
              Full Name: ''
              Logon Script: ''
              Profile Path: ''
              Home Directory: ''
              Home Directory Drive: ''
              Logon Server: ''
              Logon Domain Name: 'WINDOMAIN.LOCAL'
            Client Info:
              Name: 'Administrator'
              Client ID: 2022-11-21 13:52:00 +0000
            Pac Server Checksum:
              Signature: \x04\xe5\xab\x06\x1c\x7a\x90\x9a\x26\xb1\x22\xc2
            Pac Privilege Server Checksum:
              Signature: \x71\x0b\xb1\x83\x85\x82\x57\xf4\x10\x21\xbd\x7e
```
Now we can see much more such as the specific `Flags` used and the `Group IDs`.

## Inspecting Network Traffic (Via Wireshark)

Another method of viewing the contents of a ticket is to analyze the network traffic with Wireshark.
This is especially useful in cases where you may not have a ccache or kirbi file containing the ticket on disk
and your only option is to view it as it's being sent. 

To view the decrypted tickets in wireshark you're going to need a keytab file with the decryption key.
There's a handful of ways to get this keytab file including one documented on
the [Wireshark wiki](https://wiki.wireshark.org/Kerberos.md#how-to-create-keytab-file) itself,
but we have a module built right into metasploit that can do this for you as well.
Let's quickly go over the keytab module `modules/auxiliary/admin/kerberos/keytab`, at it's core it has three functions, `LIST` `ADD` and `EXPORT`.
For our purpose of creating a new keytab file for wireshark to use we'll focus on the `ADD` function.

To create a keytab you're going to need:
- The Kerberos principal name
- The Kerberos Realm
- The password

Alternatively if you don't have the password but do know the key:
- The Kerberos principal name
- The Kerberos Realm
- The key
- The keys encryption type

Example usage with password:
```
msf6 auxiliary(admin/kerberos/keytab) > run action=ADD keytab_file=./example.keytab principal=Administrator realm=DEMO.LOCAL enctype=ALL password=p4$$w0rd
```

Example usage with key:
```
msf6 auxiliary(admin/kerberos/keytab) > run action=ADD keytab_file=./example.keytab principal=krbtgt realm=DEMO.LOCAL enctype=AES256 key=e1c5500ffb883e713288d8037651821b9ecb0dfad89e01d1b920fe136879e33c
```
If you want a deeper dive into this module it has it's own documentation [here](link to the docs)

Now that you've created the keytab file all that's left is to tell wireshark about it.
For this open up wireshark and go to the 'Preferences' menu, expand the 'Protocols' section and look for an entry named 'KRB5'.
Once the 'KRB5' preferences are open make sure to tick "Try to decrypt Kerberos blobs" and browse to your keytab file.
Now when you are viewing Kerberos traffic in wireshark it will attempt to decrypt the data with the keytab file you've provided.
Anything highlighted in blue means it was successfully decrypted, anything in yellow failed to decrypt and is likely due to a missing key in the keytab.
