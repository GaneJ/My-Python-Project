Welcome To My Python Project
____________________________

[x] MKCABundle_Offline.py
    
    Description:
        Make CA Bundle Offline - For Mozilla Certificate Data.
        Base on Perl version in cURL source.

    Whats new:
        * Label didn't contain a Backslash character.
          Any backslash character has been translating into UTF-8 if its a hex value (\x).
          Any backslash character without a hex (non \x) will be written as the way it was
          (the idea based on OpenSSL or RFC).
        * Completely align certificate based on OpenSSL rule or RFC rule.
        * Open "Mozilla Certificate Data" file in binary mode and save "CA Bundle" in binary mode.
          This resolve the issue with "Mozilla Certificate Data" file contain backslash character.

    Limitation:
        * Only work on an offline "Mozilla Certificate Data" file.
        * Can not process if "Mozilla Certificate Data" file in unicode or encode with BOM.
          So, make sure "Mozilla Certificate Data" file format in UTF-8 Without BOM.
        * Only save a CA only. Non CA will not be save.
