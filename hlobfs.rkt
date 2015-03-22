#lang racket
(require natrium-crypt)
(require libkenji)
(require math)
(require "llobfs.rkt")
(provide hlobfs-handshake/server
         hlobfs-handshake/client)

;; Utility functions

(struct hlobfs-segment
  (type body) #:prefab)

(define hlobfs-distro
  (discrete-dist
   (in-range 1220)
   (for/list ([i (flnormal-sample 100.0 40.0 1220)])
     (max i 0))))

(define (hlobfs-sample)
  (list-ref (sample hlobfs-distro 1) 0))

(define (hlobfs-segment-write hlo out)
  (match hlo
    [(hlobfs-segment type body)
     (write-bytes
      (bytes-append
       (bytes type)
       (integer->integer-bytes (bytes-length body)
                               2
                               #f
                               #t)
       body) out)]))

(define (hlobfs-segment->bytes thing)
  (match thing
    [(hlobfs-segment type body)
     (bytes-append
      (bytes type)
      (integer->integer-bytes (bytes-length body)
                              2
                              #f
                              #t)
      body)]))

(define (hlobfs-junk-bytes n)
  (with-output-to-bytes
   (lambda ()
     (hlobfs-segment-write
      (hlobfs-segment 1 (make-bytes n))
      (current-output-port)))))

(define (hlobfs-segment-write/fluff hlo out)
  (define towr
    (hlobfs-segment->bytes hlo))
  (let loop ([rem towr])
    (define len (hlobfs-sample))
    (cond
      [(>= (bytes-length rem) 1220) (write-bytes rem out)]
      [(<= (bytes-length rem) len) (write-bytes
                                    (bytes-append
                                     rem
                                     (hlobfs-junk-bytes
                                      (- len (bytes-length rem)))) out)]
      [else (write-bytes rem out 0 len)
            (loop (subbytes rem len))])))

(define (hlobfs-segment-read in)
  (define hdr (read-bytes 3 in))
  (define type (bytes-ref hdr 0))
  (define len
    (+ (* 256 (bytes-ref hdr 1))
       (bytes-ref hdr 2)))
  (define toret (hlobfs-segment type (read-bytes len in)))
  toret)

;; Interface functions

(define (hlobfs-handshake/server secret _in _out)
  (define-values (in out) (llobfs-handshake/server secret _in _out))
  ;(define-values (in out) (values _in _out))
  (hlobfs-make-ports in out))

(define (hlobfs-handshake/client secret _in _out)
  (define-values (in out) (llobfs-handshake/client secret _in _out))
  ;(define-values (in out) (values _in _out))
  (hlobfs-make-ports in out))

;; Core function

(define (hlobfs-make-ports in out)
  ;; junk creator
  (define junker (make-timer-yarn))
  ;; Read and write locks
  (define read-lock (make-semaphore 1))
  (define write-lock (make-semaphore 1))
  (define input-closed? #f)
  ;; Read procedure
  (define (read-in)
    (with-handlers ([exn:fail? (lambda (ex) (set! input-closed? #t) eof)])
      (if input-closed? eof
          (let retry ()
            (match (hlobfs-segment-read in)
              ;; Body segment
              [(hlobfs-segment 0 body) body]
              ;; Junk segment, ignore
              [_ #""])))))
  ;; Write procedure
  (define (write-out bts)
    (with-semaphore write-lock
      (hlobfs-segment-write/fluff (hlobfs-segment 0 bts) out)
      (yarn-send/async junker 
                         (flvector-ref
                          (flexponential-sample 5000.0 1) 0)
                         (lambda ()
                           (when (semaphore-try-wait? write-lock)
                             (guard
                              (defer (semaphore-post write-lock))
                              (write-bytes (hlobfs-junk-bytes (hlobfs-sample)) out)))))
      (bytes-length bts)))
  ;; Thingy
  (values (make-input-port/buffered
           'hlobfs-input
           in
           read-in
           (lambda () (close-port in)))
          (make-output-port
           'hlobfs-output
           out
           (lambda (to-write start-idx end-idx buffer? breaks?)
             (handle-evt out
                         (lambda (ev)
                           (write-out (subbytes to-write start-idx end-idx)))))
           (lambda ()
             (guard
              (defer (close-port out))
              (yarn-send junker 0 yarn-suicide!))))))