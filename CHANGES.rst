Changes
-------

0.1.3 (2012-10-02)
~~~~~~~~~~~~~~~~~~

* Stop enabling `allow_agent` by default
* Stop requiring `ssh` library by default -- only when `allow_agent=True`
* Changed logic around ssh-agent: if one key is available, don't bother with any other method
* Changed logic around key file usage: if decryption fails, prompt for password
* Bug fix: ssh-agent resulted in a nonsensical error if it found no correct keys
* Introduce versioneer.py
