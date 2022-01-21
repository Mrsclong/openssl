#! /usr/bin/env perl
# Copyright 2010-2019 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# ====================================================================
# Written by Shi Chen long <shichenlong@loongson.cn> for the OpenSSL
# project.
#
# Rights for redistribution and usage in source and binary forms are
# granted according to the OpenSSL license. Warranty of any kind is
# disclaimed.
# ====================================================================


# January 2022
#
# This is drop-in LoongArch ISA replacement for crypto/bn/bn_asm.c.
# The module is designed to work with either of the "new" LoongArch ABI.
#
# In addition the code depends on preprocessor flags set up by LoongArch
# compiler driver  and therefore  can't be compiled by the GNU assembler.
#
# Performance improvement is astonishing! 'apps/openssl speed rsa dsa'
# goes way over 3 times faster!

# The former was achieved by mechanical replacement of 64-bit arithmetic 
# instructions such as mul.d, mulh.du, add.d, etc. with their 32-bit 
# counterparts and adjusting offsets denoting multiples of BN_ULONG. 
# Above mentioned >3x performance improvement naturally does not apply 
# to 32-bit code, because there is no instruction 32-bit compiler can't
# use, one has to content with 40-85% improvement depending on benchmark
# and key length, more for longer keys.
#					<shichenlong@loongson.cn>

$flavour = shift;
while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

$LD="ld.d";
$ST="st.d";
$MULD="mul.d";
$MULHD="mulh.du";
$DIVU="div.du";
$ADDU="add.d";
$SUBU="sub.d";
$SRL="srl.d";
$SLL="sll.d";
$SRLI="srli.d";
$SLLI="slli.d";
$BNSZ=8;
$PTR_ADD="addi.d";
$PTR_SUB="addi.d";
$SZREG=8;
$REG_S="st.d";
$REG_L="ld.d";

# Below is loongarch64 register layout used in the original module.
#
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("\$$_",(r4..r11));
($t0,$t1,$t2,$t3,$t4,$t5,$t6,$t7,$t8)=map("\$$_",(r12..r20));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8)=map("\$$_",(r23..r31));
($zero,$ra,$sp,$fp)=map("\$$_",(r0,r1,r3,r22));
($ta0,$ta1,$ta2,$ta3)=map("\$$_",(r8,r9,r10,r11));
#
# No special adaptation is required for O32. NUBI on the other hand
# is treated by saving/restoring ($v1,$t0..$t3).

$at=$t7;
$minus4=$t6;

$code.=<<___;

.text

.align	5
.globl	bn_mul_add_words
bn_mul_add_words:
	move	$t5,$zero 
	bge	    $a2,$zero,bn_mul_add_words_internal #if($a2>0) goto bn_mul_add_words_internal
    move    $a0,$t5
	jr	$ra

.align	5
bn_mul_add_words_internal:
___
$code.=<<___;
	$PTR_SUB $sp,$sp,-5*$SZREG
	$REG_S	$ra,$sp,4*$SZREG
	$REG_S	$t3,$sp,3*$SZREG
	$REG_S	$t2,$sp,2*$SZREG
	$REG_S	$t1,$sp,1*$SZREG
	$REG_S	$t0,$sp,0*$SZREG
___
$code.=<<___;
	li.d $minus4,-4
	and	$ta0,$a2,$minus4
	beqz	$ta0,.L_bn_mul_add_words_tail

.L_bn_mul_add_words_loop:
	$LD	$t0,$a1,0
    $LD	$t1,$a0,0
	$LD	$t2,$a1,$BNSZ
    $LD	$t3,$a0,$BNSZ
	$LD	$ta0,$a1,2*$BNSZ
    $LD	$ta1,$a0,2*$BNSZ
    $ADDU	$t1,$t1,$t5
    sltu	$t5,$t1,$t5	# All manuals say it "compares 32-bit
				# values", but it seems to work fine
				# even on 64-bit registers.
    $MULD  $at,$t0,$a3
    $MULHD $t0,$t0,$a3
	$ADDU	$t1,$t1,$at
	$ADDU	$t5,$t5,$t0
	sltu	$at,$t1,$at
	$ST	$t1,$a0,0
	$ADDU	$t5,$t5,$at

	$LD	$ta2,$a1,3*$BNSZ
	$LD	$ta3,$a0,3*$BNSZ
	$ADDU	$t3,$t3,$t5
	sltu	$t5,$t3,$t5
    $MULD  $at,$t2,$a3
    $MULHD $t2,$t2,$a3
	$ADDU	$t3,$t3,$at
	$ADDU	$t5,$t5,$t2
	sltu	$at,$t3,$at
    $ST	$t3,$a0,$BNSZ
	$ADDU	$t5,$t5,$at

	addi.d	$a2,$a2,-4
	$PTR_ADD $a0,$a0,4*$BNSZ
	$PTR_ADD $a1,$a1,4*$BNSZ
	$ADDU	$ta1,$ta1,$t5
	sltu	$t5,$ta1,$t5
    $MULD  $at,$ta0,$a3
    $MULHD $ta0,$ta0,$a3
    	
	$ADDU	$ta1,$ta1,$at
	$ADDU	$t5,$t5,$ta0
	sltu	$at,$ta1,$at
	$ST	$ta1,$a0,-2*$BNSZ
	$ADDU	$t5,$t5,$at


	and	$ta0,$a2,$minus4
	$ADDU	$ta3,$ta3,$t5
	sltu	$t5,$ta3,$t5
    $MULD  $at,$ta2,$a3
    $MULHD $ta2,$ta2,$a3
    
	$ADDU	$ta3,$ta3,$at
	$ADDU	$t5,$t5,$ta2
	sltu	$at,$ta3,$at
	$ST	$ta3,$a0,-$BNSZ
	$ADDU	$t5,$t5,$at
	blt	$zero,$ta0,.L_bn_mul_add_words_loop #跳转指令,因此需要调整下一条延迟指令槽到上面

	beqz	$a2,.L_bn_mul_add_words_return

.L_bn_mul_add_words_tail:
	$LD	$t0,$a1,0
	$LD	$t1,$a0,0
	addi.d	$a2,$a2,-1
	$ADDU	$t1,$t1,$t5
	sltu	$t5,$t1,$t5
    $MULD  $at,$t0,$a3
    $MULHD $t0,$t0,$a3
	$ADDU	$t1,$t1,$at
	$ADDU	$t5,$t5,$t0
	sltu	$at,$t1,$at
	$ST	$t1,$a0,0
	$ADDU	$t5,$t5,$at
	beqz	$a2,.L_bn_mul_add_words_return

	$LD	$t0,$a1,$BNSZ
	$LD	$t1,$a0,$BNSZ
	addi.d	$a2,$a2,-1
	$ADDU	$t1,$t1,$t5
	sltu	$t5,$t1,$t5
    $MULD  $at,$t0,$a3
    $MULHD $t0,$t0,$a3
	$ADDU	$t1,$t1,$at
	$ADDU	$t5,$t5,$t0
	sltu	$at,$t1,$at
	$ST	$t1,$a0,$BNSZ
	$ADDU	$t5,$t5,$at
	beqz	$a2,.L_bn_mul_add_words_return

	$LD	$t0,$a1,2*$BNSZ
	$LD	$t1,$a0,2*$BNSZ
	$ADDU	$t1,$t1,$t5
	sltu	$t5,$t1,$t5
    $MULD  $at,$t0,$a3
    $MULHD $t0,$t0,$a3
	$ADDU	$t1,$t1,$at
	$ADDU	$t5,$t5,$t0
	sltu	$at,$t1,$at
	$ST	$t1,$a0,2*$BNSZ
	$ADDU	$t5,$t5,$at

.L_bn_mul_add_words_return:
___
$code.=<<___;
    $REG_L  $ra,$sp,4*$SZREG
	$REG_L	$t3,$sp,3*$SZREG
	$REG_L	$t2,$sp,2*$SZREG
	$REG_L	$t1,$sp,1*$SZREG
	$REG_L	$t0,$sp,0*$SZREG
	$PTR_ADD $sp,$sp,5*$SZREG
___
$code.=<<___;
	move	$a0,$t5
	jr	$ra

.align 5
.globl bn_mul_words
bn_mul_words:
   move $t5,$zero
   blt $zero,$a2,bn_mul_words_internal
   move $a0,$t5
   jr $ra

.align 5
bn_mul_words_internal:
___
$code.=<<___;
    $PTR_SUB $sp,$sp,-5*$SZREG                                                
    $REG_S  $ra,$sp,4*$SZREG
    $REG_S  $t3,$sp,3*$SZREG
    $REG_S  $t2,$sp,2*$SZREG
    $REG_S  $t1,$sp,1*$SZREG
    $REG_S  $t0,$sp,0*$SZREG
___
$code.=<<___;
    li.d  $minus4,-4
    and $ta0,$a2,$minus4
    beqz    $ta0,.L_bn_mul_words_tail

.L_bn_mul_words_loop:
    $LD $t0,$a1,0
    $LD $t2,$a1,$BNSZ
    $LD $ta0,$a1,2*$BNSZ
    $LD $ta2,$a1,3*$BNSZ
    $MULD   $at,$t0,$a3
    $MULHD  $t0,$t0,$a3
    $ADDU   $t5,$t5,$at
    sltu    $t1,$t5,$at
    $ST     $t5,$a0,0
    $ADDU   $t5,$t1,$t0

    addi.d  $a2,$a2,-4
    $PTR_ADD $a0,$a0,4*$BNSZ
    $PTR_ADD $a1,$a1,4*$BNSZ
    $MULD   $at,$t2,$a3
    $MULHD  $t2,$t2,$a3
    $ADDU   $t5,$t5,$at
    sltu    $t3,$t5,$at
    $ST     $t5,$a0,-3*$BNSZ
    $ADDU   $t5,$t3,$t2

    $MULD   $at,$ta0,$a3
    $MULHD  $ta0,$ta0,$a3
    $ADDU   $t5,$t5,$at
    sltu    $ta1,$t5,$at
    $ST     $t5,$a0,-2*$BNSZ
    $ADDU   $t5,$ta1,$ta0

    and $ta0,$a2,$minus4
    $MULD   $at,$ta2,$a3
    $MULHD  $ta2,$ta2,$a3
    $ADDU   $t5,$t5,$at
    sltu    $ta3,$t5,$at
    $ST     $t5,$a0,-$BNSZ
    $ADDU   $t5,$ta3,$ta2
    blt     $zero,$ta0,.L_bn_mul_words_loop
    beqz    $a2,.L_bn_mul_words_return

.L_bn_mul_words_tail:
    $LD $t0,$a1,0
    addi.d  $a2,$a2,-1
    $MULD   $at,$t0,$a3
    $MULHD  $t0,$t0,$a3
    $ADDU   $t5,$t5,$at
    sltu    $t1,$t5,$at
    $ST     $t5,$a0,0
    $ADDU   $t5,$t1,$t0
    beqz    $a2,.L_bn_mul_words_return

    $LD     $t0,$a1,$BNSZ
    addi.d  $a2,$a2,-1
    $MULD   $at,$t0,$a3
    $MULHD  $t0,$t0,$a3
    $ADDU   $t5,$t5,$at
    sltu    $t1,$t5,$at
    $ST     $t5,$a0,$BNSZ
    $ADDU   $t5,$t1,$t0
    beqz    $a2,.L_bn_mul_words_return

    $LD     $t0,$a1,2*$BNSZ
    $MULD   $at,$t0,$a3
    $MULHD  $t0,$t0,$a3
    $ADDU   $t5,$t5,$at
    sltu    $t1,$t5,$at
    $ST     $t5,$a0,2*$BNSZ
    $ADDU   $t5,$t1,$t0

.L_bn_mul_words_return:
___
$code.=<<___;
    $REG_L  $ra,$sp,4*$SZREG
    $REG_L  $t3,$sp,3*$SZREG
    $REG_L  $t2,$sp,2*$SZREG
    $REG_L  $t1,$sp,1*$SZREG
    $REG_L  $t0,$sp,0*$SZREG
    $PTR_ADD $sp,$sp,5*$SZREG
___
$code.=<<___;
    move $a0,$t5
    jr $ra

.align  5
.globl  bn_sqr_words
bn_sqr_words:
    move    $t5,$zero
    blt     $zero,$a2,bn_sqr_words_internal
    move    $a0,$t5
    jr  $ra

.align  5
bn_sqr_words_internal:
___
$code.=<<___;
    $PTR_SUB $sp,$sp,-5*$SZREG
    $REG_S  $ra,$sp,4*$SZREG
    $REG_S  $t3,$sp,3*$SZREG
    $REG_S  $t2,$sp,2*$SZREG
    $REG_S  $t1,$sp,1*$SZREG
    $REG_S  $t0,$sp,0*$SZREG
___
$code.=<<___;
    li.d  $minus4,-4
    and $ta0,$a2,$minus4
    beqz    $ta0,.L_bn_sqr_words_tail

.L_bn_sqr_words_loop:
    $LD $t0,$a1,0
    $LD $t2,$a1,$BNSZ
    $LD $ta0,$a1,2*$BNSZ
    $LD $ta2,$a1,3*$BNSZ
    $MULD   $t1,$t0,$t0
    $MULHD  $t0,$t0,$t0
    $ST $t1,$a0,0
    $ST $t0,$a0,$BNSZ
    
    addi.d $a2,$a2,-4
    $PTR_ADD $a0,$a0,8*$BNSZ
    $PTR_ADD $a1,$a1,4*$BNSZ
    $MULD   $t3,$t2,$t2
    $MULHD  $t2,$t2,$t2
    $ST $t3,$a0,-6*$BNSZ
    $ST $t2,$a0,-5*$BNSZ

    $MULD   $ta1,$ta0,$ta0
    $MULHD  $ta0,$ta0,$ta0
    $ST $ta1,$a0,-4*$BNSZ
    $ST $ta0,$a0,-3*$BNSZ

    and $ta0,$a2,$minus4
    $MULD   $ta3,$ta2,$ta2
    $MULHD  $ta2,$ta2,$ta2
    $ST $ta3,$a0,-2*$BNSZ

    $ST $ta2,$a0,-$BNSZ
    blt $zero,$ta0,.L_bn_sqr_words_loop

    beqz    $a2,.L_bn_sqr_words_return

.L_bn_sqr_words_tail:
    $LD $t0,$a1,0
    addi.d $a2,$a2,-1
    $MULD   $t1,$t0,$t0
    $MULHD  $t0,$t0,$t0
    $ST $t1,$a0,0
    $ST $t0,$a0,$BNSZ
    beqz    $a2,.L_bn_sqr_words_return

    $LD $t0,$a1,$BNSZ
    addi.d $a2,$a2,-1
    $MULD   $t1,$t0,$t0
    $MULHD  $t0,$t0,$t0
    $ST $t1,$a0,2*$BNSZ
    $ST $t0,$a0,3*$BNSZ
    beqz    $a2,.L_bn_sqr_words_return

    $LD $t0,$a1,2*$BNSZ
    $MULD   $t1,$t0,$t0
    $MULHD  $t0,$t0,$t0
    $ST $t1,$a0,4*$BNSZ
    $ST $t0,$a0,5*$BNSZ

.L_bn_sqr_words_return:
___
$code.=<<___;
    $REG_L  $ra,$sp,4*$SZREG
    $REG_L  $t3,$sp,3*$SZREG
    $REG_L  $t2,$sp,2*$SZREG
    $REG_L  $t1,$sp,1*$SZREG
    $REG_L  $t0,$sp,0*$SZREG
    $PTR_ADD $sp,$sp,5*$SZREG
___
$code.=<<___;
    move $a0,$t5
    jr  $ra

.align  5
.globl  bn_add_words
bn_add_words:
    move    $t5,$zero
    bgtz    $a3,bn_add_words_internal
    move    $a0,$t5
    jr  $ra

.align  5
bn_add_words_internal:
___
$code.=<<___;
    $PTR_SUB $sp,$sp,-5*$SZREG
    $REG_S  $ra,$sp,4*$SZREG
    $REG_S  $t3,$sp,3*$SZREG
    $REG_S  $t2,$sp,2*$SZREG
    $REG_S  $t1,$sp,1*$SZREG
    $REG_S  $t0,$sp,0*$SZREG
___
$code.=<<___;
    li.d  $minus4,-4
    and $at,$a3,$minus4
    beqz    $at,.L_bn_add_words_tail

.L_bn_add_words_loop:
    $LD $t0,$a1,0
    $LD $ta0,$a2,0
    addi.d  $a3,$a3,-4
    $LD $t1,$a1,$BNSZ
    and $at,$a3,$minus4
    $LD $t2,$a1,2*$BNSZ
    $PTR_ADD $a2,$a2,4*$BNSZ
    $LD $t3,$a1,3*$BNSZ
    $PTR_ADD $a0,$a0,4*$BNSZ
    $LD $ta1,$a2,-3*$BNSZ
    $PTR_ADD $a1,$a1,4*$BNSZ
    $LD $ta2,$a2,-2*$BNSZ
    $LD $ta3,$a2,-$BNSZ
    $ADDU   $ta0,$ta0,$t0
    sltu    $t8,$ta0,$t0
    $ADDU   $t0,$ta0,$t5
    sltu    $t5,$t0,$ta0
    $ST     $t0,$a0,-4*$BNSZ
    $ADDU   $t5,$t5,$t8

    $ADDU   $ta1,$ta1,$t1
    sltu    $t4,$ta1,$t1
    $ADDU   $t1,$ta1,$t5
    sltu    $t5,$t1,$ta1
    $ST     $t1,$a0,-3*$BNSZ
    $ADDU   $t5,$t5,$t4

    $ADDU   $ta2,$ta2,$t2
    sltu    $t8,$ta2,$t2
    $ADDU   $t2,$ta2,$t5
    sltu    $t5,$t2,$ta2
    $ST     $t2,$a0,-2*$BNSZ
    $ADDU   $t5,$t5,$t8

    $ADDU   $ta3,$ta3,$t3
    sltu    $t4,$ta3,$t3
    $ADDU   $t3,$ta3,$t5
    sltu    $t5,$t3,$ta3
    $ST     $t3,$a0,-$BNSZ

    $ADDU   $t5,$t5,$t4
    bgtz    $at,.L_bn_add_words_loop
    beqz    $a3,.L_bn_add_words_return

.L_bn_add_words_tail:
    $LD     $t0,$a1,0
    $LD     $ta0,$a2,0
    $ADDU   $ta0,$ta0,$t0
    addi.d  $a3,$a3,-1
    sltu    $t8,$ta0,$t0
    $ADDU   $t0,$ta0,$t5
    sltu    $t5,$t0,$ta0
    $ST     $t0,$a0,0
    $ADDU   $t5,$t5,$t8
    beqz    $a3,.L_bn_add_words_return

    $LD     $t1,$a1,$BNSZ
    $LD     $ta1,$a2,$BNSZ
    $ADDU   $ta1,$ta1,$t1
    addi.d  $a3,$a3,-1
    sltu    $t4,$ta1,$t1
    $ADDU   $t1,$ta1,$t5
    sltu    $t5,$t1,$ta1
    $ST     $t1,$a0,$BNSZ
    $ADDU   $t5,$t5,$t4
    beqz    $a3,.L_bn_add_words_return

    $LD     $t2,$a1,2*$BNSZ
    $LD     $ta2,$a2,2*$BNSZ
    $ADDU   $ta2,$ta2,$t2
    sltu    $t8,$ta2,$t2
    $ADDU   $t2,$ta2,$t5
    sltu    $t5,$t2,$ta2
    $ST     $t2,$a0,2*$BNSZ
    $ADDU   $t5,$t5,$t8

.L_bn_add_words_return:
___
$code.=<<___;
    $REG_L  $ra,$sp,4*$SZREG
    $REG_L  $t3,$sp,3*$SZREG
    $REG_L  $t2,$sp,2*$SZREG
    $REG_L  $t1,$sp,1*$SZREG
    $REG_L  $t0,$sp,0*$SZREG
    $PTR_ADD $sp,$sp,5*$SZREG
___
$code.=<<___;
    move    $a0,$t5
    jr  $ra

.align  5
.globl  bn_sub_words
bn_sub_words:
    move    $t5,$zero
    bgtz    $a3,bn_sub_words_internal
    move    $a0,$zero
    jr  $ra

.align  5
bn_sub_words_internal:
___
$code.=<<___;
    $PTR_SUB $sp,$sp,-5*$SZREG
    $REG_S  $ra,$sp,4*$SZREG
    $REG_S  $t3,$sp,3*$SZREG
    $REG_S  $t2,$sp,2*$SZREG
    $REG_S  $t1,$sp,1*$SZREG
    $REG_S  $t0,$sp,0*$SZREG
___
$code.=<<___;
    li.d  $minus4,-4
    and $at,$a3,$minus4
    beqz    $at,.L_bn_sub_words_tail

.L_bn_sub_words_loop:
    $LD $t0,$a1,0
    $LD $ta0,$a2,0
    addi.d $a3,$a3,-4
    $LD $t1,$a1,$BNSZ
    and $at,$a3,$minus4
    $LD $t2,$a1,2*$BNSZ
    $PTR_ADD    $a2,$a2,4*$BNSZ
    $LD $t3,$a1,3*$BNSZ
    $PTR_ADD    $a0,$a0,4*$BNSZ
    $LD $ta1,$a2,-3*$BNSZ
    $PTR_ADD    $a1,$a1,4*$BNSZ
    $LD $ta2,$a2,-2*$BNSZ
    $LD $ta3,$a2,-$BNSZ
    sltu    $t8,$t0,$ta0
    $SUBU   $ta0,$t0,$ta0
    $SUBU   $t0,$ta0,$t5
    sltu    $t5,$ta0,$t0
    $ST $t0,$a0,-4*$BNSZ
    $ADDU   $t5,$t5,$t8

    sltu    $t4,$t1,$ta1
    $SUBU   $ta1,$t1,$ta1
    $SUBU   $t1,$ta1,$t5
    sltu    $t5,$ta1,$t1
    $ST $t1,$a0,-3*$BNSZ
    $ADDU   $t5,$t5,$t4

    sltu    $t8,$t2,$ta2
    $SUBU   $ta2,$t2,$ta2
    $SUBU   $t2,$ta2,$t5
    sltu    $t5,$ta2,$t2
    $ST $t2,$a0,-2*$BNSZ
    $ADDU   $t5,$t5,$t8

    sltu    $t4,$t3,$ta3
    $SUBU   $ta3,$t3,$ta3
    $SUBU   $t3,$ta3,$t5
    sltu    $t5,$ta3,$t3
    $ST $t3,$a0,-$BNSZ

    $ADDU   $t5,$t5,$t4
    bgtz    $at,.L_bn_sub_words_loop
    beqz    $a3,.L_bn_sub_words_return

.L_bn_sub_words_tail:
    $LD $t0,$a1,0
    $LD $ta0,$a2,0
    addi.d $a3,$a3,-1
    sltu    $t8,$t0,$ta0
    $SUBU   $ta0,$t0,$ta0
    $SUBU   $t0,$ta0,$t5
    sltu    $t5,$ta0,$t0
    $ST $t0,$a0,0
    $ADDU   $t5,$t5,$t8
    beqz    $a3,.L_bn_sub_words_return

    $LD $t1,$a1,$BNSZ
    addi.d  $a3,$a3,-1
    $LD $ta1,$a2,$BNSZ
    sltu    $t4,$t1,$ta1
    $SUBU   $ta1,$t1,$ta1
    $SUBU   $t1,$ta1,$t5
    sltu    $t5,$ta1,$t1
    $ST $t1,$a0,$BNSZ
    $ADDU   $t5,$t5,$t4
    beqz    $a3,.L_bn_sub_words_return

    $LD $t2,$a1,2*$BNSZ
    $LD $ta2,$a2,2*$BNSZ
    sltu    $t8,$t2,$ta2
    $SUBU   $ta2,$t2,$ta2
    $SUBU   $t2,$ta2,$t5
    sltu    $t5,$ta2,$t2
    $ST $t2,$a0,2*$BNSZ
    $ADDU   $t5,$t5,$t8

.L_bn_sub_words_return:
___
$code.=<<___;
    $REG_L  $ra,$sp,4*$SZREG
    $REG_L  $t3,$sp,3*$SZREG
    $REG_L  $t2,$sp,2*$SZREG
    $REG_L  $t1,$sp,1*$SZREG
    $REG_L  $t0,$sp,0*$SZREG
    $PTR_ADD $sp,$sp,5*$SZREG
___
$code.=<<___;
    move    $a0,$t5
    jr  $ra

.align  5
.globl  bn_div_words
bn_div_words:
    li.d  $t5,-1  # I would rather signal div-by-zero
                # which can be done with 'break 7'
    bnez    $a2,bn_div_words_internal
    move    $a0,$t5
    jr  $ra

bn_div_words_internal:
    $PTR_SUB $sp,$sp,-6*$SZREG
    $REG_S  $s8,$sp,5*$SZREG
    $REG_S  $ra,$sp,4*$SZREG
    $REG_S  $t3,$sp,3*$SZREG
    $REG_S  $t2,$sp,2*$SZREG
    $REG_S  $t1,$sp,1*$SZREG
    $REG_S  $t0,$sp,0*$SZREG
___
$code.=<<___;
    move    $s8,$zero
    move    $t4,$s8
    bltz    $a2,.L_bn_div_words_body
    $SLLI   $a2,$a2,1
    addi.d  $t4,$t4,1
    bgtz    $a2,.-8

    sub.d   $t1,$zero,$t4
    li.d      $t2,-1
    $SLL    $t2,$t2,$t1
    and     $t2,$t2,$a0
    $SRL    $at,$a1,$t1
    beqz    $t2,.+8
    break   6       # signal overflow
    $SLL    $a0,$a0,$t4
    $SLL    $a1,$a1,$t4
    or      $a0,$a0,$at
___
$QT=$ta0;
$HH=$ta1;
$DH=$s8;
$code.=<<___;
.L_bn_div_words_body:
    $SRLI   $DH,$a2,4*$BNSZ # bits
    sltu    $at,$a0,$a2
    xori    $at,$at,1
    beqz    $at,.+8
    $SUBU   $a0,$a0,$a2

    li.d  $QT,-1
    $SRLI    $HH,$a0,4*$BNSZ # bits
    $SRLI    $QT,$QT,4*$BNSZ # q=0xffffffff
    beq $DH,$HH,.L_bn_div_words_skip_div1
    div.du  $QT,$a0,$DH

.L_bn_div_words_skip_div1:
    $SLLI   $t3,$a0,4*$BNSZ #bits
    $SRLI   $at,$a1,4*$BNSZ # bits
    or      $t3,$t3,$at
    $MULD   $t0,$a2,$QT
    $MULHD  $t1,$a2,$QT

.L_bn_div_words_inner_loop1:
    sltu    $t2,$t3,$t0
    xor     $t8,$HH,$t1
    sltui   $t8,$t8,1
    sltu    $at,$HH,$t1
    and     $t2,$t2,$t8
    sltu    $t5,$t0,$a2
    or      $at,$at,$t2
    $SUBU   $t1,$t1,$t5
    beqz    $at,.L_bn_div_words_inner_loop1_done
    $SUBU   $t0,$t0,$a2
    addi.d  $QT,$QT,-1
    b   .L_bn_div_words_inner_loop1

.L_bn_div_words_inner_loop1_done:
    $SLLI   $a1,$a1,4*$BNSZ # bits
    $SUBU   $a0,$t3,$t0
    $SLLI   $t5,$QT,4*$BNSZ # bits

    li.d  $QT,-1
    $SRLI   $HH,$a0,4*$BNSZ # bits
    $SRLI   $QT,$QT,4*$BNSZ # q=0xffffffff
    beq $DH,$HH,.L_bn_div_words_skip_div2
    div.du  $QT,$a0,$DH

.L_bn_div_words_skip_div2:
    $SLLI   $t3,$a0,4*$BNSZ # bits
    $SRLI   $at,$a1,4*$BNSZ # bits
    or      $t3,$t3,$at
    $MULD   $t0,$a2,$QT
    $MULHD  $t1,$a2,$QT

.L_bn_div_words_inner_loop2:
    sltu    $t2,$t3,$t0
    xor     $t8,$HH,$t1
    sltui   $t8,$t8,1
    sltu    $at,$HH,$t1
    and     $t2,$t2,$t8
    sltu    $s8,$t0,$a2
    or      $at,$at,$t2
    $SUBU   $t1,$t1,$s8
    beqz    $at,.L_bn_div_words_inner_loop2_done
    $SUBU   $t0,$t0,$a2
    addi.d   $QT,$QT,-1
    b   .L_bn_div_words_inner_loop2

.L_bn_div_words_inner_loop2_done:
    $SUBU   $a0,$t3,$t0
    or      $t5,$t5,$QT
    $SRL    $s8,$a0,$t4 # $v1 contains remainder if anybody wants it
    $SRL    $a2,$a2,$t4     # restore $a2
    move    $a1,$s8
___
$code.=<<___;
    $REG_L  $s8,$sp,5*$SZREG
    $REG_L  $ra,$sp,4*$SZREG
    $REG_L  $t3,$sp,3*$SZREG
    $REG_L  $t2,$sp,2*$SZREG
    $REG_L  $t1,$sp,1*$SZREG
    $REG_L  $t0,$sp,0*$SZREG
    $PTR_ADD $sp,$sp,6*$SZREG
___
$code.=<<___;
    move    $a0,$t5
    jr  $ra
___
undef $HH; undef $QT; undef $DH;

($a_0,$a_1,$a_2,$a_3)=($t0,$t1,$t2,$t3);
($b_0,$b_1,$b_2,$b_3)=($ta0,$ta1,$ta2,$ta3);

($a_4,$a_5,$a_6,$a_7)=($s0,$s2,$s4,$a1); # once we load a[7], no use for $a1
($b_4,$b_5,$b_6,$b_7)=($s1,$s3,$s5,$a2); # once we load b[7], no use for $a2

($t_1,$t_2,$c_1,$c_2,$c_3)=($t8,$t4,$t5,$t6,$a3);

$code.=<<___;

.align  5
.globl  bn_mul_comba8
bn_mul_comba8:
___
$code.=<<___;
    $PTR_SUB $sp,$sp,-11*$SZREG
    $REG_S  $ra,$sp,10*$SZREG
    $REG_S  $s5,$sp,9*$SZREG
    $REG_S  $s4,$sp,8*$SZREG
    $REG_S  $s3,$sp,7*$SZREG
    $REG_S  $s2,$sp,6*$SZREG
    $REG_S  $s1,$sp,5*$SZREG
    $REG_S  $s0,$sp,4*$SZREG
    $REG_S  $t3,$sp,3*$SZREG
    $REG_S  $t2,$sp,2*$SZREG
        sha1_asm_src    => add("sha512-mips.S"), 
    $REG_S  $t1,$sp,1*$SZREG
    $REG_S  $t0,$sp,0*$SZREG
___
$code.=<<___;
    $LD $a_0,$a1,0
    $LD $a_1,$a1,$BNSZ
    $LD $a_2,$a1,2*$BNSZ
    $LD $a_3,$a1,3*$BNSZ
    $LD $a_4,$a1,4*$BNSZ
    $LD $a_5,$a1,5*$BNSZ
    $LD $a_6,$a1,6*$BNSZ
    $LD $a_7,$a1,7*$BNSZ
    $LD $b_0,$a2,0
    $LD $b_1,$a2,$BNSZ
    $LD $b_2,$a2,2*$BNSZ
    $LD $b_3,$a2,3*$BNSZ
    $LD $b_4,$a2,4*$BNSZ
    $LD $b_5,$a2,5*$BNSZ
    $LD $b_6,$a2,6*$BNSZ
    $LD $b_7,$a2,7*$BNSZ

    $MULD   $c_1,$a_0,$b_0  # mul_add_c(a[0],b[0],c1,c2,c3);
    $MULHD  $c_2,$a_0,$b_0

    $MULD   $t_1,$a_0,$b_1  # mul_add_c(a[0],b[1],c2,c3,c1);
    $MULHD  $t_2,$a_0,$b_1

    $ADDU   $c_2,$c_2,$t_1
    sltu    $at,$c_2,$t_1
    $ADDU   $c_3,$t_2,$at
    $ST $c_1,$a0,0          # r[0] = c1;

    $MULD   $t_1,$a_1,$b_0  # mul_add_c(a[1],b[0],c2,c3,c1);
    $MULHD  $t_2,$a_1,$b_0
    $ADDU   $c_2,$c_2,$t_1
    sltu    $at,$c_2,$t_1

    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_3,$c_3,$t_2
    sltu    $c_1,$c_3,$t_2
    $ST $c_2,$a0,$BNSZ  # r[1]=c2;

    $MULD   $t_1,$a_2,$b_0  # mul_add_c(a[2],b[0],c3,c1,c2);
    $MULHD  $t_2,$a_2,$b_0

    $ADDU   $c_3,$c_3,$t_1
    sltu    $at,$c_3,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_1,$c_1,$t_2

    $MULD   $t_1,$a_1,$b_1  # mul_add_c(a[1],b[1],c3,c1,c2);
    $MULHD  $t_2,$a_1,$b_1
    $ADDU   $c_3,$c_3,$t_1
    sltu    $at,$c_3,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_1,$c_1,$t_2
    sltu    $c_2,$c_1,$t_2
    $MULD   $t_1,$a_0,$b_2  # mul_add_c(a[0],b[2],c3,c1,c2);
    $MULHD  $t_2,$a_0,$b_2
    $ADDU   $c_3,$c_3,$t_1
    sltu    $at,$c_3,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_1,$c_1,$t_2
    sltu    $at,$c_1,$t_2
    $ADDU   $c_2,$c_2,$at
    $ST $c_3,$a0,2*$BNSZ    # r[2]=c3;

    $MULD   $t_1,$a_0,$b_3  # mul_add_c(a[0],b[3],c1,c2,c3);
    $MULHD  $t_2,$a_0,$b_3
        sha1_asm_src    => add("sha512-mips.S"), 
    $ADDU   $c_1,$c_1,$t_1
    sltu    $at,$c_1,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_2,$c_2,$t_2
    sltu    $c_3,$c_2,$t_2
    $MULD   $t_1,$a_1,$b_2  # mul_add_c(a[1],b[2],c1,c2,c3);
    $MULHD  $t_2,$a_1,$b_2
    $ADDU   $c_1,$c_1,$t_1
    sltu    $at,$c_1,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_2,$c_2,$t_2
    sltu    $at,$c_2,$t_2
    $ADDU   $c_3,$c_3,$at
    $MULD   $t_1,$a_2,$b_1  # mul_add_c(a[2],b[1],c1,c2,c3);
    $MULHD  $t_2,$a_2,$b_1
    $ADDU   $c_1,$c_1,$t_1
    sltu    $at,$c_1,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_2,$c_2,$t_2
    sltu    $at,$c_2,$t_2
    $ADDU   $c_3,$c_3,$at
    $MULD   $t_1,$a_3,$b_0  # mul_add_c(a[3],b[0],c1,c2,c3);
    $MULHD  $t_2,$a_3,$b_0
    $ADDU   $c_1,$c_1,$t_1
    sltu    $at,$c_1,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_2,$c_2,$t_2
    sltu    $at,$c_2,$t_2
    $ADDU   $c_3,$c_3,$at
    $ST $c_1,$a0,3*$BNSZ    # r[3]=c1;

    $MULD   $t_1,$a_4,$b_0  # mul_add_c(a[4],b[0],c2,c3,c1);
    $MULHD  $t_2,$a_4,$b_0
    $ADDU   $c_2,$c_2,$t_1
    sltu    $at,$c_2,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_3,$c_3,$t_2
    sltu    $c_1,$c_3,$t_2
    $MULD   $t_1,$a_3,$b_1  # mul_add_c(a[3],b[1],c2,c3,c1);
    $MULHD  $t_2,$a_3,$b_1
    $ADDU   $c_2,$c_2,$t_1
    sltu    $at,$c_2,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_3,$c_3,$t_2
    sltu    $at,$c_3,$t_2
    $ADDU   $c_1,$c_1,$at
    $MULD   $t_1,$a_2,$b_2  # mul_add_c(a[2],b[2],c2,c3,c1);
    $MULHD  $t_2,$a_2,$b_2
        sha1_asm_src    => add("sha512-mips.S"), 
    $ADDU   $c_2,$c_2,$t_1
    sltu    $at,$c_2,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_3,$c_3,$t_2
    sltu    $at,$c_3,$t_2
    $ADDU   $c_1,$c_1,$at
    $MULD   $t_1,$a_1,$b_3  # mul_add_c(a[1],b[3],c2,c3,c1);
    $MULHD  $t_2,$a_1,$b_3
    $ADDU   $c_2,$c_2,$t_1
    sltu    $at,$c_2,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_3,$c_3,$t_2
    sltu    $at,$c_3,$t_2
    $ADDU   $c_1,$c_1,$at
    $MULD   $t_1,$a_0,$b_4  # mul_add_c(a[0],b[4],c2,c3,c1);
    $MULHD  $t_2,$a_0,$b_4
    $ADDU   $c_2,$c_2,$t_1
    sltu    $at,$c_2,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_3,$c_3,$t_2
    sltu    $at,$c_3,$t_2
    $ADDU   $c_1,$c_1,$at
    $ST $c_2,$a0,4*$BNSZ    # r[4]=c2;

    $MULD   $t_1,$a_0,$b_5  # mul_add_c(a[0],b[5],c3,c1,c2);
    $MULHD  $t_2,$a_0,$b_5
    $ADDU   $c_3,$c_3,$t_1
    sltu    $at,$c_3,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_1,$c_1,$t_2
    sltu    $c_2,$c_1,$t_2
    $MULD   $t_1,$a_1,$b_4  # mul_add_c(a[1],b[4],c3,c1,c2);
    $MULHD  $t_2,$a_1,$b_4
    $ADDU   $c_3,$c_3,$t_1
    sltu    $at,$c_3,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_1,$c_1,$t_2
    sltu    $at,$c_1,$t_2
    $ADDU   $c_2,$c_2,$at
    $MULD   $t_1,$a_2,$b_3  # mul_add_c(a[2],b[3],c3,c1,c2);
    $MULHD  $t_2,$a_2,$b_3
    $ADDU   $c_3,$c_3,$t_1
    sltu    $at,$c_3,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_1,$c_1,$t_2
    sltu    $at,$c_1,$t_2
    $ADDU   $c_2,$c_2,$at
    $MULD   $t_1,$a_3,$b_2
    $MULHD  $t_2,$a_3,$b_2
    $ADDU   $c_3,$c_3,$t_1
    sltu    $at,$c_3,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_1,$c_1,$t_2
    sltu    $at,$c_1,$t_2
    $ADDU   $c_2,$c_2,$at
    $MULD   $t_1,$a_4,$b_1  # mul_add_c(a[4],b[1],c3,c1,c2);
    $MULHD  $t_2,$a_4,$b_1
    $ADDU   $c_3,$c_3,$t_1
    sltu    $at,$c_3,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_1,$c_1,$t_2
    sltu    $at,$c_1,$t_2
    $ADDU   $c_2,$c_2,$at
    $MULD   $t_1,$a_5,$b_0  # mul_add_c(a[5],b[0],c3,c1,c2);
    $MULHD  $t_2,$a_5,$b_0
    $ADDU   $c_3,$c_3,$t_1
    sltu    $at,$c_3,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_1,$c_1,$t_2
    sltu    $at,$c_1,$t_2
    $ADDU   $c_2,$c_2,$at
    $ST $c_3,$a0,5*$BNSZ    # r[5]=c3;

    $MULD   $t_1,$a_6,$b_0
    $MULHD  $t_2,$a_6,$b_0
    $ADDU   $c_1,$c_1,$t_1
    sltu    $at,$c_1,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_2,$c_2,$t_2
    sltu    $c_3,$c_2,$t_2
    $MULD   $t_1,$a_5,$b_1  # mul_add_c(a[5],b[1],c1,c2,c3);
    $MULHD  $t_2,$a_5,$b_1
    $ADDU   $c_1,$c_1,$t_1
    sltu    $at,$c_1,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_2,$c_2,$t_2
    sltu    $at,$c_2,$t_2
    $ADDU   $c_3,$c_3,$at
    $MULD   $t_1,$a_4,$b_2
    $MULHD  $t_2,$a_4,$b_2
    $ADDU   $c_1,$c_1,$t_1
    sltu    $at,$c_1,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_2,$c_2,$t_2
    sltu    $at,$c_2,$t_2
    $ADDU   $c_3,$c_3,$at
    $MULD   $t_1,$a_3,$b_3  # mul_add_c(a[3],b[3],c1,c2,c3);
    $MULHD  $t_2,$a_3,$b_3
    $ADDU   $c_1,$c_1,$t_1
    sltu    $at,$c_1,$t_1
    $ADDU   $t_2,$t_2,$at
        sha1_asm_src    => add("sha512-mips.S"), 
    $ADDU   $c_2,$c_2,$t_2
    sltu    $at,$c_2,$t_2
    $ADDU   $c_3,$c_3,$at
    $MULD   $t_1,$a_2,$b_4  # mul_add_c(a[2],b[4],c1,c2,c3);
    $MULHD  $t_2,$a_2,$b_4
    $ADDU   $c_1,$c_1,$t_1
    sltu    $at,$c_1,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_2,$c_2,$t_2
    sltu    $at,$c_2,$t_2
    $ADDU   $c_3,$c_3,$at
    $MULD   $t_1,$a_1,$b_5  # mul_add_c(a[1],b[5],c1,c2,c3);
    $MULHD  $t_2,$a_1,$b_5
    $ADDU   $c_1,$c_1,$t_1
    sltu    $at,$c_1,$t_1
        sha1_asm_src    => add("sha512-mips.S"), 
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_2,$c_2,$t_2
    sltu    $at,$c_2,$t_2
    $ADDU   $c_3,$c_3,$at
    $MULD   $t_1,$a_0,$b_6
    $MULHD  $t_2,$a_0,$b_6
    $ADDU   $c_1,$c_1,$t_1
    sltu    $at,$c_1,$t_1
    $ADDU   $t_2,$t_2,$at
    $ADDU   $c_2,$c_2,$t_2
    sltu    $at,$c_2,$t_2
    $ADDU   $c_3,$c_3,$at
    $ST $c_1,$a0,6*$BNSZ    # r[6]=c1;


        sha1_asm_src    => add("sha512-mips.S"), 
	$MULD	$t_1,$a_0,$b_7
	$MULHD	$t_2,$a_0,$b_7  # mul_add_c(a[0],b[7],c2,c3,c1);
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$c_1,$c_3,$t_2
	$MULD	$t_1,$a_1,$b_6  # mul_add_c(a[1],b[6],c2,c3,c1);
	$MULHD	$t_2,$a_1,$b_6
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$MULD	$t_1,$a_2,$b_5  # mul_add_c(a[2],b[5],c2,c3,c1);
	$MULHD	$t_2,$a_2,$b_5
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$MULD	$t_1,$a_3,$b_4  # mul_add_c(a[3],b[4],c2,c3,c1);
	$MULHD	$t_2,$a_3,$b_4
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$MULD	$t_1,$a_4,$b_3  # mul_add_c(a[4],b[3],c2,c3,c1);
	$MULHD	$t_2,$a_4,$b_3
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$MULD	$t_1,$a_5,$b_2  # mul_add_c(a[5],b[2],c2,c3,c1);
	$MULHD	$t_2,$a_5,$b_2
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$MULD	$t_1,$a_6,$b_1  # mul_add_c(a[6],b[1],c2,c3,c1);
	$MULHD	$t_2,$a_6,$b_1
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$MULD	$t_1,$a_7,$b_0  # mul_add_c(a[7],b[0],c2,c3,c1);
	$MULHD	$t_2,$a_7,$b_0
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$ST	$c_2,$a0,7*$BNSZ	# r[7]=c2;

	$MULD	$t_1,$a_7,$b_1  # mul_add_c(a[7],b[1],c3,c1,c2);
	$MULHD	$t_2,$a_7,$b_1
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$c_2,$c_1,$t_2
	$MULD	$t_1,$a_6,$b_2  # mul_add_c(a[6],b[2],c3,c1,c2);
	$MULHD	$t_2,$a_6,$b_2
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$MULD	$t_1,$a_5,$b_3  # mul_add_c(a[5],b[3],c3,c1,c2);
	$MULHD	$t_2,$a_5,$b_3
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$MULD	$t_1,$a_4,$b_4  # mul_add_c(a[4],b[4],c3,c1,c2);
	$MULHD	$t_2,$a_4,$b_4
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$MULD	$t_1,$a_3,$b_5  # mul_add_c(a[3],b[5],c3,c1,c2);
	$MULHD	$t_2,$a_3,$b_5
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$MULD	$t_1,$a_2,$b_6  # mul_add_c(a[2],b[6],c3,c1,c2);
	$MULHD	$t_2,$a_2,$b_6
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$MULD	$t_1,$a_1,$b_7  # mul_add_c(a[1],b[7],c3,c1,c2);  
	$MULHD	$t_2,$a_1,$b_7
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$ST	$c_3,$a0,8*$BNSZ	# r[8]=c3;

	$MULD	$t_1,$a_2,$b_7  # mul_add_c(a[2],b[7],c1,c2,c3);
	$MULHD	$t_2,$a_2,$b_7
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$c_3,$c_2,$t_2
	$MULD	$t_1,$a_3,$b_6  # mul_add_c(a[3],b[6],c1,c2,c3);
	$MULHD	$t_2,$a_3,$b_6
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$at,$c_2,$t_2
	$ADDU	$c_3,$c_3,$at
	$MULD	$t_1,$a_4,$b_5  # mul_add_c(a[4],b[5],c1,c2,c3);
	$MULHD	$t_2,$a_4,$b_5
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$at,$c_2,$t_2
	$ADDU	$c_3,$c_3,$at
	$MULD	$t_1,$a_5,$b_4  # mul_add_c(a[5],b[4],c1,c2,c3);
	$MULHD	$t_2,$a_5,$b_4
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$at,$c_2,$t_2
	$ADDU	$c_3,$c_3,$at
	$MULD	$t_1,$a_6,$b_3  # mul_add_c(a[6],b[3],c1,c2,c3);
	$MULHD	$t_2,$a_6,$b_3
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$at,$c_2,$t_2
	$ADDU	$c_3,$c_3,$at
	$MULD	$t_1,$a_7,$b_2  # mul_add_c(a[7],b[2],c1,c2,c3);
	$MULHD	$t_2,$a_7,$b_2
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$at,$c_2,$t_2
	$ADDU	$c_3,$c_3,$at
	$ST	$c_1,$a0,9*$BNSZ	# r[9]=c1;

	$MULD	$t_1,$a_7,$b_3  # mul_add_c(a[7],b[3],c2,c3,c1);
	$MULHD	$t_2,$a_7,$b_3
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$c_1,$c_3,$t_2
	$MULD	$t_1,$a_6,$b_4  # mul_add_c(a[6],b[4],c2,c3,c1);
	$MULHD	$t_2,$a_6,$b_4
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$MULD	$t_1,$a_5,$b_5  # mul_add_c(a[5],b[5],c2,c3,c1);
	$MULHD	$t_2,$a_5,$b_5
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$MULD	$t_1,$a_4,$b_6  # mul_add_c(a[4],b[6],c2,c3,c1);
	$MULHD	$t_2,$a_4,$b_6
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$MULD	$t_1,$a_3,$b_7  # mul_add_c(a[3],b[7],c2,c3,c1);
	$MULHD	$t_2,$a_3,$b_7
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$ST	$c_2,$a0,10*$BNSZ	# r[10]=c2;

	$MULD	$t_1,$a_4,$b_7  # mul_add_c(a[4],b[7],c3,c1,c2);
	$MULHD	$t_2,$a_4,$b_7
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$c_2,$c_1,$t_2
	$MULD	$t_1,$a_5,$b_6  # mul_add_c(a[5],b[6],c3,c1,c2);
	$MULHD	$t_2,$a_5,$b_6
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$MULD	$t_1,$a_6,$b_5  # mul_add_c(a[6],b[5],c3,c1,c2);
	$MULHD	$t_2,$a_6,$b_5
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$MULD	$t_1,$a_7,$b_4  # mul_add_c(a[7],b[4],c3,c1,c2);
	$MULHD	$t_2,$a_7,$b_4
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$ST	$c_3,$a0,11*$BNSZ	# r[11]=c3;

	$MULD	$t_1,$a_7,$b_5  # mul_add_c(a[7],b[5],c1,c2,c3);  
	$MULHD	$t_2,$a_7,$b_5
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$c_3,$c_2,$t_2
	$MULD	$t_1,$a_6,$b_6  # mul_add_c(a[6],b[6],c1,c2,c3);
	$MULHD	$t_2,$a_6,$b_6
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$at,$c_2,$t_2
	$ADDU	$c_3,$c_3,$at
	$MULD	$t_1,$a_5,$b_7  # mul_add_c(a[5],b[7],c1,c2,c3);
	$MULHD	$t_2,$a_5,$b_7
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$at,$c_2,$t_2
	$ADDU	$c_3,$c_3,$at
	$ST	$c_1,$a0,12*$BNSZ	# r[12]=c1;

	$MULD	$t_1,$a_6,$b_7  # mul_add_c(a[6],b[7],c2,c3,c1);
	$MULHD	$t_2,$a_6,$b_7
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$c_1,$c_3,$t_2
	$MULD	$t_1,$a_7,$b_6  # mul_add_c(a[7],b[6],c2,c3,c1);
	$MULHD	$t_2,$a_7,$b_6
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$ST	$c_2,$a0,13*$BNSZ	# r[13]=c2;

	$MULD	$t_1,$a_7,$b_7  # mul_add_c(a[7],b[7],c3,c1,c2);
	$MULHD	$t_2,$a_7,$b_7
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	$ST	$c_3,$a0,14*$BNSZ	# r[14]=c3;
	$ST	$c_1,$a0,15*$BNSZ	# r[15]=c1;
___
$code.=<<___;
    $REG_L  $ra,$sp,10*$SZREG
    $REG_L  $s5,$sp,9*$SZREG
    $REG_L  $s4,$sp,8*$SZREG
    $REG_L  $s3,$sp,7*$SZREG
    $REG_L  $s2,$sp,6*$SZREG
    $REG_L  $s1,$sp,5*$SZREG
    $REG_L  $s0,$sp,4*$SZREG
    $REG_L  $t3,$sp,3*$SZREG
    $REG_L  $t2,$sp,2*$SZREG
    $REG_L  $t1,$sp,1*$SZREG
    $REG_L  $t0,$sp,0*$SZREG
    $PTR_ADD $sp,$sp,11*$SZREG
    jr  $ra
___
$code.=<<___;
.align  5
.globl  bn_mul_comba4
bn_mul_comba4:
___
$code.=<<___;
    $PTR_SUB $sp,$sp,-5*$SZREG
    $REG_S  $ra,$sp,4*$SZREG
    $REG_S  $t3,$sp,3*$SZREG
    $REG_S  $t2,$sp,2*$SZREG
    $REG_S  $t1,$sp,1*$SZREG
    $REG_S  $t0,$sp,0*$SZREG
___
$code.=<<___;
    $LD $a_0,$a1,0
    $LD $a_1,$a1,$BNSZ
    $LD $a_2,$a1,2*$BNSZ
    $LD $a_3,$a1,3*$BNSZ
    $LD $b_0,$a2,0
    $LD $b_1,$a2,$BNSZ
    $LD $b_2,$a2,2*$BNSZ
    $LD $b_3,$a2,3*$BNSZ
    $MULD   $c_1,$a_0,$b_0  # mul_add_c(a[0],b[0],c1,c2,c3);
    $MULHD  $c_2,$a_0,$b_0
    $ST $c_1,$a0,0;

    $MULD   $t_1,$a_0,$b_1  # mul_add_c(a[0],b[1],c2,c3,c1);
	$MULHD	$t_2,$a_0,$b_1
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$c_3,$t_2,$at
	$MULD	$t_1,$a_1,$b_0  # mul_add_c(a[1],b[0],c2,c3,c1);
	$MULHD	$t_2,$a_1,$b_0
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$c_1,$c_3,$t_2
	$ST	$c_2,$a0,$BNSZ

	$MULD	$t_1,$a_2,$b_0  # mul_add_c(a[2],b[0],c3,c1,c2);
	$MULHD	$t_2,$a_2,$b_0
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	$MULD	$t_1,$a_1,$b_1  # mul_add_c(a[1],b[1],c3,c1,c2);
	$MULHD	$t_2,$a_1,$b_1
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$c_2,$c_1,$t_2
	$MULD	$t_1,$a_0,$b_2  # mul_add_c(a[0],b[2],c3,c1,c2);
	$MULHD	$t_2,$a_0,$b_2
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$ST	$c_3,$a0,2*$BNSZ

	$MULD	$t_1,$a_0,$b_3  # mul_add_c(a[0],b[3],c1,c2,c3);
	$MULHD	$t_2,$a_0,$b_3
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$c_3,$c_2,$t_2
	$MULD	$t_1,$a_1,$b_2  # mul_add_c(a[1],b[2],c1,c2,c3);
	$MULHD	$t_2,$a_1,$b_2
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$at,$c_2,$t_2
	$ADDU	$c_3,$c_3,$at
	$MULD	$t_1,$a_2,$b_1  # mul_add_c(a[2],b[1],c1,c2,c3);
	$MULHD	$t_2,$a_2,$b_1
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$at,$c_2,$t_2
	$ADDU	$c_3,$c_3,$at
	$MULD	$t_1,$a_3,$b_0  # mul_add_c(a[3],b[0],c1,c2,c3);
	$MULHD	$t_2,$a_3,$b_0
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$at,$c_2,$t_2
	$ADDU	$c_3,$c_3,$at
	$ST	$c_1,$a0,3*$BNSZ

	$MULD	$t_1,$a_3,$b_1  # mul_add_c(a[3],b[1],c2,c3,c1);
	$MULHD	$t_2,$a_3,$b_1
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$c_1,$c_3,$t_2
	$MULD	$t_1,$a_2,$b_2  # mul_add_c(a[2],b[2],c2,c3,c1);
	$MULHD	$t_2,$a_2,$b_2
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$MULD	$t_1,$a_1,$b_3  # mul_add_c(a[1],b[3],c2,c3,c1);
	$MULHD	$t_2,$a_1,$b_3
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$ST	$c_2,$a0,4*$BNSZ

	$MULD	$t_1,$a_2,$b_3  # mul_add_c(a[2],b[3],c3,c1,c2);
	$MULHD	$t_2,$a_2,$b_3
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$c_2,$c_1,$t_2
	$MULD	$t_1,$a_3,$b_2  # mul_add_c(a[3],b[2],c3,c1,c2);
	$MULHD	$t_2,$a_3,$b_2
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$ST	$c_3,$a0,5*$BNSZ

	$MULD	$t_1,$a_3,$b_3  # mul_add_c(a[3],b[3],c1,c2,c3);
	$MULHD	$t_2,$a_3,$b_3
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	$ST	$c_1,$a0,6*$BNSZ
	$ST	$c_2,$a0,7*$BNSZ
___
$code.=<<___;
	$REG_L	$ra,$sp,4*$SZREG
	$REG_L	$t3,$sp,3*$SZREG
	$REG_L	$t2,$sp,2*$SZREG
	$REG_L	$t1,$sp,1*$SZREG
	$REG_L	$t0,$sp,0*$SZREG
	$PTR_ADD $sp,$sp,5*$SZREG
___
$code.=<<___;
	jr	$ra
___

($a_4,$a_5,$a_6,$a_7)=($b_0,$b_1,$b_2,$b_3);

sub add_c2 () {
my ($hi,$lo,$c0,$c1,$c2,
    $warm,  # !$warm denotes first call with specific sequence of
            # $c_[XYZ] when there is no Z-carry to accumulate yet;
    $an,$bn # these two are arguments for multiplication which
            # result is used in *next* step [which is why it's
            # commented as "forward multiplication" below];
    )=@_;
$code.=<<___;
    $ADDU   $c0,$c0,$lo
	sltu	$at,$c0,$lo
    #$MULD   $lo,$an,$bn # forward multiplication
    #$MULHD  $hi,$an,$bn
	$ADDU	$c0,$c0,$lo
	$ADDU	$at,$at,$hi
	sltu	$lo,$c0,$lo
	$ADDU	$c1,$c1,$at
	$ADDU	$hi,$hi,$lo
___
$code.=<<___	if (!$warm);
	sltu	$c2,$c1,$at
	$ADDU	$c1,$c1,$hi
___
$code.=<<___	if ($warm);
	sltu	$at,$c1,$at
	$ADDU	$c1,$c1,$hi
	$ADDU	$c2,$c2,$at
___
$code.=<<___;
	sltu	$hi,$c1,$hi
	$ADDU	$c2,$c2,$hi
    $MULD   $lo,$an,$bn # forward multiplication
    $MULHD  $hi,$an,$bn
___
}

$code.=<<___;
.align  5
.globl  bn_sqr_comba8
bn_sqr_comba8:
___
$code.=<<___;
    $PTR_SUB $sp,$sp,-5*$SZREG
    $REG_S  $ra,$sp,4*$SZREG
    $REG_S  $t3,$sp,3*$SZREG
    $REG_S  $t2,$sp,2*$SZREG
    $REG_S  $t1,$sp,1*$SZREG
    $REG_S  $t0,$sp,0*$SZREG
___
$code.=<<___;
	$LD	$a_0,$a1,0
	$LD	$a_1,$a1,$BNSZ
	$LD	$a_2,$a1,2*$BNSZ
	$LD	$a_3,$a1,3*$BNSZ
	$LD	$a_4,$a1,4*$BNSZ
	$LD	$a_5,$a1,5*$BNSZ
	$LD	$a_6,$a1,6*$BNSZ
	$LD	$a_7,$a1,7*$BNSZ
	$MULD	$c_1,$a_0,$a_0  # mul_add_c(a[0],b[0],c1,c2,c3);
	$MULHD	$c_2,$a_0,$a_0
	$ST	$c_1,$a0,0

	$MULD	$t_1,$a_0,$a_1  # mul_add_c2(a[0],b[1],c2,c3,c1);
	$MULHD	$t_2,$a_0,$a_1
	slt	$c_1,$t_2,$zero
	$SLLI	$t_2,$t_2,1
	slt	$a2,$t_1,$zero
	$ADDU	$t_2,$t_2,$a2
	$SLLI	$t_1,$t_1,1
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$c_3,$t_2,$at
	$ST	$c_2,$a0,$BNSZ
	$MULD	$t_1,$a_2,$a_0  # mul_add_c2(a[2],b[0],c3,c1,c2);
	$MULHD	$t_2,$a_2,$a_0
___
	&add_c2($t_2,$t_1,$c_3,$c_1,$c_2,0,$a_1,$a_1);		# mul_add_c(a[1],b[1],c3,c1,c2);
$code.=<<___;
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$ST	$c_3,$a0,2*$BNSZ
	$MULD	$t_1,$a_0,$a_3  # mul_add_c2(a[0],b[3],c1,c2,c3);
	$MULHD	$t_2,$a_0,$a_3
___
	&add_c2($t_2,$t_1,$c_1,$c_2,$c_3,0,$a_1,$a_2);		# mul_add_c2(a[1],b[2],c1,c2,c3);
	&add_c2($t_2,$t_1,$c_1,$c_2,$c_3,1,$a_4,$a_0);		# mul_add_c2(a[4],b[0],c2,c3,c1);
$code.=<<___;
	$ST	$c_1,$a0,3*$BNSZ
___
	&add_c2($t_2,$t_1,$c_2,$c_3,$c_1,0,$a_3,$a_1);		# mul_add_c2(a[3],b[1],c2,c3,c1);
	&add_c2($t_2,$t_1,$c_2,$c_3,$c_1,1,$a_2,$a_2);		# mul_add_c(a[2],b[2],c2,c3,c1);
$code.=<<___;
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$ST	$c_2,$a0,4*$BNSZ
	$MULD	$t_1,$a_0,$a_5  # mul_add_c2(a[0],b[5],c3,c1,c2);
	$MULHD	$t_2,$a_0,$a_5
___
	&add_c2($t_2,$t_1,$c_3,$c_1,$c_2,0,$a_1,$a_4);		# mul_add_c2(a[1],b[4],c3,c1,c2);
	&add_c2($t_2,$t_1,$c_3,$c_1,$c_2,1,$a_2,$a_3);		# mul_add_c2(a[2],b[3],c3,c1,c2);
	&add_c2($t_2,$t_1,$c_3,$c_1,$c_2,1,$a_6,$a_0);		# mul_add_c2(a[6],b[0],c1,c2,c3);
$code.=<<___;
	$ST	$c_3,$a0,5*$BNSZ
___
	&add_c2($t_2,$t_1,$c_1,$c_2,$c_3,0,$a_5,$a_1);		# mul_add_c2(a[5],b[1],c1,c2,c3);
	&add_c2($t_2,$t_1,$c_1,$c_2,$c_3,1,$a_4,$a_2);		# mul_add_c2(a[4],b[2],c1,c2,c3);
	&add_c2($t_2,$t_1,$c_1,$c_2,$c_3,1,$a_3,$a_3);		# mul_add_c(a[3],b[3],c1,c2,c3);
$code.=<<___;
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$at,$c_2,$t_2
	$ADDU	$c_3,$c_3,$at
	$ST	$c_1,$a0,6*$BNSZ
	$MULD	$t_1,$a_0,$a_7  # mul_add_c2(a[0],b[7],c2,c3,c1);
	$MULHD	$t_2,$a_0,$a_7
___
	&add_c2($t_2,$t_1,$c_2,$c_3,$c_1,0,$a_1,$a_6);		# mul_add_c2(a[1],b[6],c2,c3,c1);
	&add_c2($t_2,$t_1,$c_2,$c_3,$c_1,1,$a_2,$a_5);		# mul_add_c2(a[2],b[5],c2,c3,c1);
	&add_c2($t_2,$t_1,$c_2,$c_3,$c_1,1,$a_3,$a_4);		# mul_add_c2(a[3],b[4],c2,c3,c1);
	&add_c2($t_2,$t_1,$c_2,$c_3,$c_1,1,$a_7,$a_1);		# mul_add_c2(a[7],b[1],c3,c1,c2);
$code.=<<___;
	$ST	$c_2,$a0,7*$BNSZ
___
	&add_c2($t_2,$t_1,$c_3,$c_1,$c_2,0,$a_6,$a_2);		# mul_add_c2(a[6],b[2],c3,c1,c2);
	&add_c2($t_2,$t_1,$c_3,$c_1,$c_2,1,$a_5,$a_3);		# mul_add_c2(a[5],b[3],c3,c1,c2);
	&add_c2($t_2,$t_1,$c_3,$c_1,$c_2,1,$a_4,$a_4);		# mul_add_c(a[4],b[4],c3,c1,c2);
$code.=<<___;
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$ST	$c_3,$a0,8*$BNSZ
	$MULD	$t_1,$a_2,$a_7  # mul_add_c2(a[2],b[7],c1,c2,c3);
	$MULHD	$t_2,$a_2,$a_7
___
	&add_c2($t_2,$t_1,$c_1,$c_2,$c_3,0,$a_3,$a_6);		# mul_add_c2(a[3],b[6],c1,c2,c3);
	&add_c2($t_2,$t_1,$c_1,$c_2,$c_3,1,$a_4,$a_5);		# mul_add_c2(a[4],b[5],c1,c2,c3);
	&add_c2($t_2,$t_1,$c_1,$c_2,$c_3,1,$a_7,$a_3);		# mul_add_c2(a[7],b[3],c2,c3,c1);
$code.=<<___;
	$ST	$c_1,$a0,9*$BNSZ
___
	&add_c2($t_2,$t_1,$c_2,$c_3,$c_1,0,$a_6,$a_4);		# mul_add_c2(a[6],b[4],c2,c3,c1);
	&add_c2($t_2,$t_1,$c_2,$c_3,$c_1,1,$a_5,$a_5);		# mul_add_c(a[5],b[5],c2,c3,c1);
$code.=<<___;
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$ST	$c_2,$a0,10*$BNSZ
	$MULD	$t_1,$a_4,$a_7  # mul_add_c2(a[4],b[7],c3,c1,c2);
	$MULHD	$t_2,$a_4,$a_7
___
	&add_c2($t_2,$t_1,$c_3,$c_1,$c_2,0,$a_5,$a_6);		# mul_add_c2(a[5],b[6],c3,c1,c2);
	&add_c2($t_2,$t_1,$c_3,$c_1,$c_2,1,$a_7,$a_5);		# mul_add_c2(a[7],b[5],c1,c2,c3);
$code.=<<___;
	$ST	$c_3,$a0,11*$BNSZ
___
	&add_c2($t_2,$t_1,$c_1,$c_2,$c_3,0,$a_6,$a_6);		# mul_add_c(a[6],b[6],c1,c2,c3);
$code.=<<___;
	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	sltu	$at,$c_2,$t_2
	$ADDU	$c_3,$c_3,$at
	$ST	$c_1,$a0,12*$BNSZ
	$MULD	$t_1,$a_6,$a_7  # mul_add_c2(a[6],b[7],c2,c3,c1);
	$MULHD	$t_2,$a_6,$a_7
___
	&add_c2($t_2,$t_1,$c_2,$c_3,$c_1,0,$a_7,$a_7);		# mul_add_c(a[7],b[7],c3,c1,c2);
$code.=<<___;
	$ST	$c_2,$a0,13*$BNSZ
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	$ST	$c_3,$a0,14*$BNSZ
	$ST	$c_1,$a0,15*$BNSZ
___
$code.=<<___;
	$REG_L	$ra,$sp,4*$SZREG
	$REG_L	$t3,$sp,3*$SZREG
	$REG_L	$t2,$sp,2*$SZREG
	$REG_L	$t1,$sp,1*$SZREG
	$REG_L	$t0,$sp,0*$SZREG
	$PTR_ADD $sp,$sp,5*$SZREG
	jr	$ra
___
$code.=<<___;
.align  5
.globl  bn_sqr_comba4
bn_sqr_comba4:
___
$code.=<<___;
    $PTR_SUB $sp,$sp,-5*$SZREG
    $REG_S  $ra,$sp,4*$SZREG
    $REG_S  $t3,$sp,3*$SZREG
    $REG_S  $t2,$sp,2*$SZREG
    $REG_S  $t1,$sp,1*$SZREG
    $REG_S  $t0,$sp,0*$SZREG
___
$code.=<<___;
	$LD	$a_0,$a1,0
	$LD	$a_1,$a1,$BNSZ
	$LD	$a_2,$a1,2*$BNSZ
	$LD	$a_3,$a1,3*$BNSZ
	$MULD	$c_1,$a_0,$a_0  # mul_add_c(a[0],b[0],c1,c2,c3);
	$MULHD	$c_2,$a_0,$a_0
	$ST	$c_1,$a0,0

	$MULD	$t_1,$a_0,$a_1  # mul_add_c2(a[0],b[1],c2,c3,c1);
	$MULHD	$t_2,$a_0,$a_1
	slt	$c_1,$t_2,$zero
	$SLLI	$t_2,$t_2,1
	slt	$a2,$t_1,$zero
	$ADDU	$t_2,$t_2,$a2
	$SLLI	$t_1,$t_1,1
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$c_3,$t_2,$at
	$ST	$c_2,$a0,$BNSZ
	$MULD	$t_1,$a_2,$a_0  # mul_add_c2(a[2],b[0],c3,c1,c2);
	$MULHD	$t_2,$a_2,$a_0
___
	&add_c2($t_2,$t_1,$c_3,$c_1,$c_2,0,$a_1,$a_1);		# mul_add_c(a[1],b[1],c3,c1,c2);
$code.=<<___;
	$ADDU	$c_3,$c_3,$t_1
	sltu	$at,$c_3,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_1,$c_1,$t_2
	sltu	$at,$c_1,$t_2
	$ADDU	$c_2,$c_2,$at
	$ST	$c_3,$a0,2*$BNSZ
	$MULD	$t_1,$a_0,$a_3  # mul_add_c2(a[0],b[3],c1,c2,c3);
	$MULHD	$t_2,$a_0,$a_3
___
	&add_c2($t_2,$t_1,$c_1,$c_2,$c_3,0,$a_1,$a_2);		# mul_add_c2(a2[1],b[2],c1,c2,c3);
	&add_c2($t_2,$t_1,$c_1,$c_2,$c_3,1,$a_3,$a_1);		# mul_add_c2(a[3],b[1],c2,c3,c1);
$code.=<<___;
	$ST	$c_1,$a0,3*$BNSZ
___
	&add_c2($t_2,$t_1,$c_2,$c_3,$c_1,0,$a_2,$a_2);		# mul_add_c(a[2],b[2],c2,c3,c1);
$code.=<<___;
	$ADDU	$c_2,$c_2,$t_1
	sltu	$at,$c_2,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_3,$c_3,$t_2
	sltu	$at,$c_3,$t_2
	$ADDU	$c_1,$c_1,$at
	$ST	$c_2,$a0,4*$BNSZ
	$MULD	$t_1,$a_2,$a_3  # mul_add_c2(a[2],b[3],c3,c1,c2);
	$MULHD	$t_2,$a_2,$a_3
___
	&add_c2($t_2,$t_1,$c_3,$c_1,$c_2,0,$a_3,$a_3);		# mul_add_c(a[3],b[3],c1,c2,c3);
$code.=<<___;
	$ST	$c_3,$a0,5*$BNSZ

	$ADDU	$c_1,$c_1,$t_1
	sltu	$at,$c_1,$t_1
	$ADDU	$t_2,$t_2,$at
	$ADDU	$c_2,$c_2,$t_2
	$ST	$c_1,$a0,6*$BNSZ
	$ST	$c_2,$a0,7*$BNSZ
___
$code.=<<___;
	$REG_L	$t4,$sp,4*$SZREG
	$REG_L	$t3,$sp,3*$SZREG
	$REG_L	$t2,$sp,2*$SZREG
	$REG_L	$t1,$sp,1*$SZREG
	$REG_L	$t0,$sp,0*$SZREG
	$PTR_ADD $sp,$sp,5*$SZREG
___
$code.=<<___;
	jr	$ra
___
print $code;
close STDOUT;
