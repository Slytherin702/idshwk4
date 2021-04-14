@load base / frameworks / sumstats

事件 http_reply（c：连接，版本：字符串，代码：计数，原因：字符串）{
    SumStats :: observe（“ response ”，SumStats :: Key（$ host = c $ id $ orig_h），SumStats :: Observation（$ num = 1））;
    如果（代码==  404）{
        SumStats :: observe（“ response404 ”，SumStats :: Key（$ host = c $ id $ orig_h），SumStats :: Observation（$ num = 1））;
        SumStats :: observe（“ responseUnique404 ”，SumStats :: Key（$ host = c $ id $ orig_h），SumStats :: Observation（$ str = c $ http $ uri））;
    }
}

事件 zeek_init（）{
    本地r_All =  SumStats :: Reducer（$ stream = “ response ”，$ apply = set（SumStats :: SUM））;
    本地r_404 =  SumStats :: Reducer（$ stream = “ response404 ”，$ apply = set（SumStats :: SUM））;
    本地r_Unique_404 =  SumStats :: Reducer（$ stream = “ responseUnique404 ”，$ apply = set（SumStats :: UNIQUE））;

    SumStats :: create（[$ name = “ http_lookup ”，$ epoch = 10min，$ reducers = set（r_All，r_404，r_Unique_404），$ epoch_result（ts：time，key：SumStats :: Key，结果：SumStats :: Result ）= {
        本地r1 = result [ “ response ” ];
        本地r2 = result [ “ response404 ” ];
        本地r3 = result [ “ responseUnique404 ” ];
        如果（r2 $ sum >  2）{
            如果（r2 $ sum / r1 $ sum >  0.2）{
                如果（r3 $ unique / r2 $ sum >  0.5）{
                    打印 fmt（“  ％s是具有％d url上的％.0f扫描尝试次数的扫描器”，key $ host，r2 $ sum，r3 $ unique）；
                } 
            }
        }
    }]）;
}
