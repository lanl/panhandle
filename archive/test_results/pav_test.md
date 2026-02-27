# using pavilion (assume already set up)

1. - Razorback: run test `pav run hpcg -c schedule.include_nodes=nid001030 -c schedule.slurm.sbatch_extra='--mem=20G --ntasks=12'`
   - Selene: run test `pav run hpcg -c schedule.slurm.sbatch_extra='--ntasks=2  --mem-per-gpu=40G --gpus-per-task=1' -c schedule.include_nodes=se003`
2. find suite id in the output
3. [ ] make sure the test passed: `pav  results --key gflops,memory,bandwidth,runtime <suite id>`
    or
   [ ] check that you got results: `pav results <suite id>`
4. get test id from that output
5. format results in json: `cat working_dir/test_runs/<test id>/results.json | jq | tee -a ../test_results.json`
