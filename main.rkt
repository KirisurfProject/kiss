#lang typed/racket/base

(require/typed/provide "kiss.rkt"
                       [kiss-handshake/server (-> Bytes Input-Port Output-Port
                                                  (Values Input-Port Output-Port))]
                       [kiss-handshake/client (-> Bytes Input-Port Output-Port
                                                  (Values Input-Port Output-Port))])

(require/typed/provide "llobfs.rkt"
                       [llobfs-handshake/server (-> Bytes Input-Port Output-Port
                                                    (Values Input-Port Output-Port))]
                       [llobfs-handshake/client (-> Bytes Input-Port Output-Port
                                                    (Values Input-Port Output-Port))])

(require/typed/provide "hlobfs.rkt"
                       [hlobfs-handshake/server (-> Bytes Input-Port Output-Port
                                                    (Values Input-Port Output-Port))]
                       [hlobfs-handshake/client (-> Bytes Input-Port Output-Port
                                                    (Values Input-Port Output-Port))])