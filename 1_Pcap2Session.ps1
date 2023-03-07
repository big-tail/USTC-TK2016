# Wei Wang (ww8137@mail.ustc.edu.cn)
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file, You
# can obtain one at http://mozilla.org/MPL/2.0/.
# ==============================================================================

foreach($f in gci 1_Pcap\USTC-TFC2016\Benign *.pcap)
{
#Session ALL Process
    0_Tool\SplitCap_2-1\SplitCap -p 50000 -b 50000 -r $f.FullName -o 2_Session\AllLayers\$($f.BaseName)-ALL
    gci 2_Session\AllLayers\$($f.BaseName)-ALL | ?{$_.Length -eq 0} | del

#Session L7 Process
    0_Tool\SplitCap_2-1\SplitCap -p 50000 -b 50000 -r $f.FullName -o 2_Session\L7\$($f.BaseName)-L7 -y L7
    gci 2_Session\L7\$($f.BaseName)-L7 | ?{$_.Length -eq 0} | del

# #Flow ALL Process
#      0_Tool\SplitCap_2-1\SplitCap -p 50000 -b 50000 -r $f.FullName -s flow -o Flow\AllLayers\$($f.BaseName)-ALL
#      gci Flow\AllLayers\$($f.BaseName)-ALL | ?{$_.Length -eq 0} | del 

# #Flow L7 Process
#      0_Tool\SplitCap_2-1\SplitCap -p 50000 -b 50000 -r $f.FullName -s flow -o Flow\L7\$($f.BaseName)-L7 -y L7
#      gci Flow\L7\$($f.BaseName)-L7 | ?{$_.Length -eq 0} | del
}

foreach($f in gci 1_Pcap\USTC-TFC2016\Malware *.pcap)
{
#Session ALL Process
    0_Tool\SplitCap_2-1\SplitCap -p 50000 -b 50000 -r $f.FullName -o 2_Session\AllLayers\$($f.BaseName)-ALL
    gci 2_Session\AllLayers\$($f.BaseName)-ALL | ?{$_.Length -eq 0} | del

#Session L7 Process
    0_Tool\SplitCap_2-1\SplitCap -p 50000 -b 50000 -r $f.FullName -o 2_Session\L7\$($f.BaseName)-L7 -y L7
    gci 2_Session\L7\$($f.BaseName)-L7 | ?{$_.Length -eq 0} | del

# #Flow ALL Process
#      0_Tool\SplitCap_2-1\SplitCap -p 50000 -b 50000 -r $f.FullName -s flow -o Flow\AllLayers\$($f.BaseName)-ALL
#      gci Flow\AllLayers\$($f.BaseName)-ALL | ?{$_.Length -eq 0} | del 

# #Flow L7 Process
#      0_Tool\SplitCap_2-1\SplitCap -p 50000 -b 50000 -r $f.FullName -s flow -o Flow\L7\$($f.BaseName)-L7 -y L7
#      gci Flow\L7\$($f.BaseName)-L7 | ?{$_.Length -eq 0} | del
}

0_Tool\finddupe -del 2_Session\AllLayers
0_Tool\finddupe -del 2_Session\L7

#0_Tool\finddupe -del Flow\AllLayers
#0_Tool\finddupe -del Flow\L7