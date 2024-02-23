#PSI
run_dh_psi_disk.sh --- you need to generate input first with "createRandomFiles.py", then convert it with "dh-convertInput"
run_dh_psi_no_disk.sh



#OPRF benchmarks
run_dh.sh
run_kkrt.sh

#FOPPRF benchmarks
run_kkrt_opprf.sh

#ToDo: Mismatch
run_dh_mismatch-32bit_classic.sh
run_dh_mismatch-32bit.sh
run_dh_mismatch_classic.sh
run_dh_mismatch.sh
run_kkrt_mmatch.sh


#For benchmarks !!!!!
s6 = "run_s6.sh"
s3 = "run_s3_linear_class.sh"
dh = "run_rist_mismatch_class.sh"
vole_s6 = check directory ../../working_vole-pdc2.tgz #join files with cat
