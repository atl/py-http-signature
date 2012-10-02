Changes
-------

0.1.3 (2012-10-02)
~~~~~~~~~~~~~~~~~~

* Stop enabling `allow_agent` by default
* Changed logic around ssh-agent: if one key is available, don't bother with any other method
* Changed logic around key file usage: if decryption fails, prompt for password
* Introduce versioneer.py
