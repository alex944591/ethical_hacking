# -*- coding: utf-8 -*-
nat = "ip nat inside source list ACL interface FastEthernet0/1 overload"
new_line=nat.replace('Fast', 'Gigabit')
print(new_line)
