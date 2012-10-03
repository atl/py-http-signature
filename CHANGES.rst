Changes
-------

0.1.4 (2012-10-03)
~~~~~~~~~~~~~~~~~~

* Account for ssh now being re-merged into paramiko: either package is acceptable (but paramiko should ideally be >= 1.8.0)

0.1.3 (2012-10-02)
~~~~~~~~~~~~~~~~~~

* Stop enabling `allow_agent` by default
* Stop requiring `ssh` package by default -- it is imported only when `allow_agent=True`
* Changed logic around ssh-agent: if one key is available, don't bother with any other authentication method
* Changed logic around key file usage: if decryption fails, prompt for password
* Bug fix: ssh-agent resulted in a nonsensical error if it found no correct keys (thanks, petervolpe)
* Introduce versioneer.py
