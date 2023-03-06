# sewing-waste-and-agriculture-leftovers

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

- 394 solves / 100 points

## Background

UDP - UNRELIABLE datagram protocol.

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2023/images/Pasted%20image%2020230304142716.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/KalmarCTF-2023/forensic/sewing-waste-and-agriculture-leftovers)-[2023.03.04|14:26:54(HKT)]
└> file swaal.pcap.gz 
swaal.pcap.gz: gzip compressed data, was "swaal.pcap", last modified: Fri Jan 27 07:17:39 2023, from Unix, original size modulo 2^32 354024
┌[siunam♥earth]-(~/ctf/KalmarCTF-2023/forensic/sewing-waste-and-agriculture-leftovers)-[2023.03.04|14:27:30(HKT)]
└> gunzip swaal.pcap.gz
┌[siunam♥earth]-(~/ctf/KalmarCTF-2023/forensic/sewing-waste-and-agriculture-leftovers)-[2023.03.04|14:27:37(HKT)]
└> file swaal.pcap   
swaal.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)
```

**It's a `pcap` packet capture file! Let's open it in WireShark:**
```shell
┌[siunam♥earth]-(~/ctf/KalmarCTF-2023/forensic/sewing-waste-and-agriculture-leftovers)-[2023.03.04|14:28:00(HKT)]
└> wireshark swaal.pcap
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2023/images/Pasted%20image%2020230304142853.png)

In here, we only see UDP traffics.

**We can extract those UDP's data via `tshark`, a command-line version of WireShark:**
```shell
┌[siunam♥earth]-(~/ctf/KalmarCTF-2023/forensic/sewing-waste-and-agriculture-leftovers)-[2023.03.04|14:35:49(HKT)]
└> tshark -r swaal.pcap -T fields -e data | tr -d '\n' | xxd -r -p         
lr{tid0_emeug

aa{_4_d0_cyeou_s

kmf_ir0yes1

kmt_u0dmur
mr4ryod0cea1u
r_fi_d_ucceoundp}

a4_is_unt_eyud
km_tuuccm_
l{tisyun_yed

ma_tseeu}
kla{i_td_r
lr_dnsoup
mtfterus
alma4idn__n
rs_eyogd

k__dsbe_1g_

mi_rs_cedmays1u
asdteedyouup

f_une_o_
mr{yn_sbyu_1p
afirtodsccmybygd
laitsbudp

aiiutcergdp
la_4od0tumab_n}
mtsy0cyp
fs_0umyeeu1

kart_ucdyeureus1n
lafi_yutce_ay_yop
amiu_0nuayur
4_r_dceedmay1n
kaifomerungp

r4frscybeuu
afirnced_myoen_
rto_ucemyysg
l_unsucc_ay
arfro_semousg_
m{_y_c_1_u
l{i4dcaen_
eyours1dp
r{rdteurng}

kiner_s

{i4out1d

{t_t_n_cmo
a{ir_tce_yen
f_sud0ms
k4y_temyureng
t_e_yeye1
amrf__0dun

lt_u_0sceyouup

alr{ftr__ceey_yng}
fiydc_ys_ud
kaiftu_meuu1}
mt_y_mb_1ngu
kiituscer
aisdtucd_up
_tistsuug
a{s0ndur1nd
kit_t_ntceeo_n_u
klft_0ne_boedp

lafin_cdbyoun
{4fu_suceme_up

ftyn_uemyey_
4i0_e_mybep
a{ftoudeyeeup
rt_in_abouud

aa{ff_o0eb_nu
lanccd_oue1_p
_yne_yu1g
_4toudnuccdg_u
al{4istddybed
if_yunuyeus_
rfsuc_b
i4ud0_se_u
alrdteeu
aruce_bug_u
s0uced_absup
ma{f0tsc_meorn

kt_ude_udp
k_no
al{iyo_ceue1_up}
kr4r_ccdm_p
ftoemaos1d
ff0sc_ao
itdn_uc_engd
_4o_d0c_y__nup
a_dntys1_
ffrydedbous
a_firttu_us_}
f4_syce_yud
_r_ou_tcc_yru
l{f4t_scag}
{__frrugdp
rir0d
ri_nteab_r_d
lr_oudt_ere

ar{i_irousd_myr1u
aa_tcdou}

ftey_yeng
lr4fu_se_aye_yeu1
4t_yud0ucdbee_su
```

Looks like we found the flag??

However, I still wasn't able to figure out the real flag...