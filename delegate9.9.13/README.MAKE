Subject: README about DeleGate
Content-Type: multipart/alternative; boundary="===="

--====
Content-Type: text/plain; charset=US-ASCII

``DeleGate Home Page'' is at http://www.delegate.org/delegate/

-- How to make DeleGate --

(0) Get and extract the latest version of DeleGate from
       <URL:ftp://ftp.etl.go.jp/pub/DeleGate/>
    in a tar+gzip format file named ``delegate*.tar.gz'' where the ``*''
    stands for a version number.

(1) Modify src/Makefile if necessary (*a,*b)
(2) Do "make" (*c,*d)
(3) You will get delegated under src/.
(4) Read tutor-en.htm and doc/Manual.txt about how to use DeleGate.

 (*a) Define ADMIN variable which will be sent on access to anonymous-FTP:
          ADMIN = mail-address-of-DeleGate-administrator

 (*b) For users who frequently update DeleGate following its revisions, not
      making changes directly to src/Makefile but making DELEGATE_CONF and
      writing your own non standard definitions in it is recommended.

 (*c) The make procedure assumes that the CC parameter defines an available
      C compiler.  If the make failed, retry with CC like follows for example:
        % make CC=gcc

 (*d) On WindowsNT/2000/95/98 with Visual C++ installed at the standard
      location, you can do make like follows:
        \delegate> make-vc   (WindowsNT/2000)
        \delegate> make-vc95 (Windows95/98)

If you have any question, ask DeleGate mailing list in English
<delegate-en@smtpgate.etl.go.jp>.  You can read the mailing list at
<URL:http://www.delegate.org/delegate/ml/delegate-en/> whether you are
the member of the list or not.

--====
Content-Type: text/plain; charset=ISO-2022-JP

``DeleGateのホームページ'' は http://www.delegate.org/delegate/ にあります。

-- DeleGate の作り方 --

(0) DeleGateの最新版を取り寄せて展開して下さい。最新版は、
       <URL:ftp://ftp.etl.go.jp/pub/DeleGate/>
    の下に、``delegate*.tar.gz'' (* の部分はバージョン番号) という名前の
    tar+gzip形式ファイルで置いてあります。

(1) src/Makefile を必要に応じて修正して下さい (*a,*b)
(2) "make" を実行して下さい。 (*c,*d)
(3) src/ の下に delegated ができます。
(4) 使い方に関しては、tutor-jp.htm と doc/Manual.txt を読んでください。

 (*a) anonymous-FTP アクセス時などに、アクセス者名として使われるアドレスを、
      以下のように定義して下さい。
          ADMIN = DeleGate管理者のメールアドレス

 (*b) DeleGate の改版に応じて頻繁に make を行うユーザは、src/Makefileを直接
　　　変更するのではなく、DELEGATE_CONF というファイルを作り、そこに標準とは
　　　異なる定義を記述しておくことをお勧めします。

 (*c) このmakeでは、CC変数が
　　　使用可能なＣコンパイラを指していることを必要とします。もしmakeが
　　　失敗したら、例えば以下のように、CCを指定してみて下さい。
      　% make CC=gcc

 (*d) WindowsNT/2000/95/98 上では、Visual C++ が標準の場所にインストールされて
      いるなら、以下のようにして make できます。
        \delegate> make-vc    (WindowsNT/2000)
        \delegate> make-vc95  (Windows95/98)

何か疑問点がありましたら、DeleGateメーリングリスト <delegate@etl.go.jp>
にお問い合わせ下さい。このMLは<URL:http://www.delegate.org/delegate/ml/>
で、会員、非会員に関わらず読む事ができます。

--====

Yutaka Sato / 佐藤豊 <ysato@etl.go.jp>
--====--
