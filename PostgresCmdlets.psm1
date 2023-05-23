function Invoke-PgQuery{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param(
        [string]$Name="postgres",
        [parameter(Mandatory=$true)]
        [string]$Query,
        [validateset("Object","Json","Raw")]
        [string]$ReturnAs,
        $Credential
    )
    
    if ($PSCmdlet.MyInvocation.BoundParameters['Credential'])
    {
        New-PgCredential -Credential $Credential -ErrorAction Stop  | Out-Null 
        $PgCredentialInfo=Get-PgCredential 
    }
    else
    {
        $PgCredentialInfo=Get-PgCredential
        if ($PgCredentialInfo -eq $null)
        {
            New-PgCredential -ErrorAction Stop | Out-Null   
        }
        
    }
    $PgCredentialInfo=Get-PgCredential
    $Credential=$PgCredentialInfo.Credential
    [string]$PgUser=$Credential.UserName
    [string]$PgPassword=GetPlainTextPassword -SecString $Credential.Password
    if ([string]::IsNullOrEmpty($PgUser) -or [string]::IsNullOrEmpty($PgPassword))
    {
        Write-Error "Credential is null or empty" -ErrorAction Stop
    }    
    $PgPathInfo=$PgCredentialInfo.PgPathInfo
    $PsqlPath=$PgPathInfo["psql.exe"]
    if ([string]::IsNullOrEmpty($PsqlPath))
    {
        Write-Error "psql.exe not found" -ErrorAction Stop
    }
    function ConvertFromJson2
    { 
        [cmdletbinding()]
        param(
            [string[]]$item
        )
          
    function ConvertFromJson3
    {
        [cmdletbinding()]
        param(
            [parameter(Mandatory=$true)]
            [string[]]$JsonString

        )
        $OutHashTable=@{}
        $JsonString | foreach{
            $Json=$_
            $OutObj=New-Object -TypeName psobject
            if (!([string]::IsNullOrEmpty($json)))
            {
                [array]$(($Json -replace "[{}]") -split ",") | foreach{
                    $JsonProperty=$_
                    if ($JsonProperty -match '"(.+)":"(.+)"')
                    {
                    
                        $PropertyName=$Matches[1]
                        $PropertyValue=$Matches[2]
                        $OutHashTable.Add($PropertyName,$PropertyValue)
                        #$OutObj | Add-Member -MemberType NoteProperty -Name $PropertyName -Value $PropertyValue
                    
                    }
                    elseif($JsonProperty -match '"(.+)":(.+)')
                    {
                        $PropertyName=$Matches[1]
                        $PropertyValue=$Matches[2]
                        $OutHashTable.Add($PropertyName,$PropertyValue)
                    
                    }
                    else
                    {
                        Write-Verbose "Incorrect json" -Verbose
                    }
                }   
            }
            #$OutObj
        
        }
        $OutHashTable
    }
        if (!([string]::IsNullOrEmpty($item)))
        {
            try
            {
                add-type -assembly system.web.extensions
                $ps_js=new-object system.web.script.serialization.javascriptSerializer    
                #The comma operator is the array construction operator in PowerShell
                return ,$ps_js.DeserializeObject($item)
            }
            catch
            {
                Write-Verbose "failed to use module system.web.extensions. Try Use ConvertFromJson3"
        
                ConvertFromJson3 -JsonString $item -ErrorAction Stop   
            }
        }
        

        
    }
    if ($PSCmdlet.MyInvocation.BoundParameters['ReturnAs'] -eq "Json" -or $PSCmdlet.MyInvocation.BoundParameters['ReturnAs'] -eq "Object" -or $PSCmdlet.MyInvocation.BoundParameters['ReturnAs'] -eq $null)
    {
        if ($Query -match ".+;$")
        {
            $Query=$Query -replace ";$"
        }
        $Query="SELECT row_to_json(T) FROM (" +$Query+ ") T" 
        
        $Query='"'+$Query+';"'
        $PsqlArgs=@(
            "--dbname $Name",
            "-qtAX",
            "--username $PgUser",
            "-w",
            "--command=$Query"
        )  
    }
    else
    {
        $Query='"'+$Query+';"'
        $PsqlArgs=@(
            "-d $Name",
            "-AX",
            "-U $PgUser",
            "-w",
            "--command=$Query"
        )  
    }
    
    Write-Verbose "$PsqlPath $PsqlArgs"
    $Result=InvokeExe -ExeFile $PsqlPath -Args $PsqlArgs -EnvVar $(@{"PGPASSWORD"=$PgPassword}) #-Encoding  1251 65001
    Write-Verbose "ExitCode: $($Result.exitcode) StdErr: $($Result.stdErr)"
    if (!($Result.exitcode -eq 0))
    {
        Write-Error "ExitCode: $($Result.exitcode) StdErr: $($Result.stdErr) StdOut: $($Result.StdOut)" -ErrorAction Stop
    }
    else
    {
        
        $OutRes=@()
        $RawResults=$Result.StdOut
        if ($PSCmdlet.MyInvocation.BoundParameters['ReturnAs'] -eq "Json" -or $PSCmdlet.MyInvocation.BoundParameters['ReturnAs'] -eq "Object" -or $PSCmdlet.MyInvocation.BoundParameters['ReturnAs'] -eq $null)
        {
            [string[]]$RawResults=$Result.StdOut -split "`n"
        }
        if ($PSCmdlet.MyInvocation.BoundParameters['ReturnAs'] -eq "Object"-or $PSCmdlet.MyInvocation.BoundParameters['ReturnAs'] -eq $null)
        {
            
            if ($PSVersionTable["PsVersion"] -gt [version]"2.0")
            {
                $OutRes+=$RawResults | ConvertFrom-Json  -ErrorAction Stop
            }
            else
            {
                $RawResults | foreach {
                    $JsonString=$_
                    Write-Debug dbg
                    $HashTableObject=ConvertFromJson2 -item $JsonString
                    if ($HashTableObject)
                    {
                        
                        $OutRes+=New-Object -TypeName psobject -Property $HashTableObject -ErrorAction Stop    
                    }
                    
                }
            }
            
            
        }
        else
        {
            $OutRes=$RawResults
        }
        
        $OutRes
    }

}
function Get-PgDatabase{
    <#
    .SYNOPSIS
        Gets a SQL database object for each database.
    .DESCRIPTION
        Gets a SQL database object for each database.
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param(
        [string]$Name,
        [switch]$ShowAll,
        [validateset("Size","Path","ConnectionLimit")]
        [string[]]$Properties,
        $Credential

    )
    if ($PSCmdlet.MyInvocation.BoundParameters['Credential'])
    {
        New-PgCredential -Credential $Credential -ErrorAction Stop  | Out-Null 
        $PgCredentialInfo=Get-PgCredential 
    }
    else
    {
        $PgCredentialInfo=Get-PgCredential
        if ($PgCredentialInfo -eq $null)
        {
            New-PgCredential -ErrorAction Stop | Out-Null   
        }
        
    }
    $PgCredentialInfo=Get-PgCredential
    $Credential=$PgCredentialInfo.Credential
    
    [string]$PgUser=$Credential.UserName
    [string]$PgPassword=GetPlainTextPassword -SecString $Credential.Password
    if ([string]::IsNullOrEmpty($PgUser) -or [string]::IsNullOrEmpty($PgPassword))
    {
        Write-Error "Credential is null or empty" -ErrorAction Stop
    }    
    [string]$DataLocation=(Invoke-PgQuery -Query "SELECT name, setting FROM pg_settings WHERE Name = 'data_directory'").setting
    #$PgFileLocation=Invoke-PgQuery -Query "SELECT name, setting FROM pg_settings WHERE category = 'File Locations'" -ReturnAs Object
    #$DataLocation=($PgFileLocation | Where-Object {$_.name -eq "data_directory"}).setting
    $DataLocation=$DataLocation -replace "/", "\"
    if ($PSBoundParameters["Name"] -ne $null)
    {
        $AllDbInfo=Invoke-PgQuery -Query  "SELECT datname,datallowconn,datconnlimit from pg_database WHERE datname = '$Name'" -ReturnAs Object
        if ($AllDbInfo.datname -eq $null)
        {
            Write-Error "$Name not found"
        }

    }
    else
    {
        [array]$AllDbInfo=Invoke-PgQuery -Query  "SELECT datname,datallowconn,datconnlimit from pg_database" -ReturnAs Object
    }
    
        $OutRes=@()
        $AllDbInfo | foreach {
            $DbName=$null
            $DbName=$_.datname
            if ($dbname)
            {
                
                $DbOid=$null
                $DbSize=$null
                $DbPath=$null
                $AllowConn=$_.datallowconn 
                $ConnectionLimit=$_.datconnlimit
                [array]$ConnectionCount=@()
                $AllConnections=Invoke-PgQuery -Query "SELECT datname FROM pg_stat_activity Where datname='$DbName'" -ReturnAs Object
                if ($AllConnections -ne $null)
                {
                    $ConnectionCount+=$AllConnections
                }
                $Res=New-Object -TypeName psobject
                $Res | Add-Member -MemberType NoteProperty -Name Name -Value $DbName
                if ($Properties -eq "Path")
                {
                    $DbOid=Invoke-PgQuery -Query  "SELECT oid from pg_database where datname = '$DbName'" -ReturnAs Object
                    $DbPath=Join-Path -Path $DataLocation -ChildPath "base\$($DbOid.oid)"
                    $Res | Add-Member -MemberType NoteProperty -Name Path  -Value $DbPath    
                }

                
                $Res | Add-Member -MemberType NoteProperty -Name ConnectionCount -Value $($ConnectionCount.Count)
                if ($Properties -eq "ConnectionLimit")
                {
                    $Res | Add-Member -MemberType NoteProperty -Name ConnectionLimit -Value $ConnectionLimit    
                }
                $Res | Add-Member -MemberType NoteProperty -Name AllowConn -Value $AllowConn
                if ($Properties -eq "Size")
                {
                    $DbSize=$((Invoke-PgQuery -Query  "select pg_database_size('$DbName')" -ReturnAs Object).pg_database_size) -as [int64]
                    $Res | Add-Member -MemberType NoteProperty -Name Size -Value $DbSize
                    $Res.psobject.typenames.insert(0,"ModulePostgresCmdlets.PostgresCmdlets.Database.List")
                }
                #Write-Debug -Debug dbg
                
                if ($PSBoundParameters["ShowAll"].IsPresent)
                {
                    $OutRes+=$Res
                    
                }
                else
                {
                    if (!($Dbname -eq "Postgres" -or $Dbname -match "^template\d$") -or $PSBoundParameters["Name"] -ne $null)
                    {
                        $OutRes+=$Res
                    }
                }
                    
            }



        }
        if ($Properties -eq "Size")
        {
            $OutRes | Sort-Object -Property Size -Descending    
        }
        else
        {
            $OutRes | Sort-Object -Property Name
        }
        
  
    
}
function Remove-PgDatabase{
    <#
    .SYNOPSIS
        Deletes the database.
    .DESCRIPTION
        Deletes the database.
    .EXAMPLE
        Get-PgDatabase | Where-Object {$_.name -match "copy"}  | Remove-PgDatabase -Confirm:$false -Force
        All databases containing "copy" in the name will be removed. There will be no deletion confirmation and existing connections will be forcibly disconnected.
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding(SupportsShouldProcess=$true,ConfirmImpact = 'High')]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        [string]$Name,
        [switch]$Force,
        $Credential

    )
    begin
    {
        if ($PSCmdlet.MyInvocation.BoundParameters['Credential'])
        {
            New-PgCredential -Credential $Credential -ErrorAction Stop  | Out-Null 
            $PgCredentialInfo=Get-PgCredential 
        }
        else
        {
            $PgCredentialInfo=Get-PgCredential
            if ($PgCredentialInfo -eq $null)
            {
                New-PgCredential -ErrorAction Stop | Out-Null   
            }
        
        }
        $PgCredentialInfo=Get-PgCredential
        $Credential=$PgCredentialInfo.Credential
        [string]$PgUser=$Credential.UserName
        [string]$PgPassword=GetPlainTextPassword -SecString $Credential.Password
        if ([string]::IsNullOrEmpty($PgUser) -or [string]::IsNullOrEmpty($PgPassword))
        {
            Write-Error "Credential is null or empty" -ErrorAction Stop
        }
        $PgPathInfo=$PgCredentialInfo.PgPathInfo
        $DropDbPath=$PgPathInfo["dropdb.exe"]
        if ([string]::IsNullOrEmpty($DropDbPath))
        {
            Write-Error "dropdb.exe not found" -ErrorAction Stop
        }
    }
    process
    {
        try
        {
            if (!([string]::IsNullOrEmpty($Name)))
            {
                $DropDbArgs=@(
                    "-U $PgUser",
                    "-w",
                    "$Name"
                )
                Write-Verbose "Remove PgDatabase $Name"
                $AllDbInfo=Invoke-PgQuery -Query  "SELECT datname from pg_database WHERE datname = '$Name'" -ReturnAs Object
                if ($AllDbInfo.datname -eq $null)
                {
                    Write-Error "$Name not found" -ErrorAction Stop
                }
                if ($PSCmdlet.ShouldProcess($Name))
                {
            
                    [array]$Connections=@()
                    $AllConnections=Invoke-PgQuery -Query  "SELECT datname FROM pg_stat_activity Where datname='$Name'" 
                    if ($AllConnections -ne $null)
                    {
                        $Connections+=$AllConnections
                    }
                    if ($Connections.Count -eq 0 -or $PSBoundParameters["Force"].Ispresent)
                    {
                        Invoke-PgQuery -Query "UPDATE pg_database SET datallowconn = false WHERE datname = '$Name'"  -ReturnAs Raw | Out-Null
                        if ($Connections.Count -ne 0)
                        {
                    
                            Invoke-PgQuery -Query "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$Name'"  | Out-Null
                        }
                        Write-Verbose "$DropDbPath $DropDbArgs"
                        $Result=InvokeExe -ExeFile $DropDbPath -Args $DropDbArgs -EnvVar $(@{"PGPASSWORD"=$PgPassword})
                        if ($Result.ExitCode -ne 0)
                        {
                            Write-Error "ExitCode: $($Result.exitcode) StdErr: $($Result.stdErr) StdOut: $($Result.StdOut)"
                        }
                        else
                        {
                            Write-Verbose "$Name base deleted"   
                        }    
                    }
                    else
                    {
                       Write-Error "$Name : The database has a non-empty list of connections. Use the -Force option to remove this database"
                    }
            
            
            
                }
                else
                {
                    Write-Verbose "Try remove database $Name"
                    Write-Verbose "$DropDbPath $DropDbArgs"
        
                }
            }
        }
        catch
        {
            Write-Error $_
        }
        
   
    }
    end
    {
    
    }
}
function New-PgDatabase{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$Name,
        [string]$Template="template0",
        $Credential

    )
        if ($name.length -gt 63)
        {
            Write-Error "The name is longer than 63 characters" -ErrorAction Stop
        }
        if ($PSCmdlet.MyInvocation.BoundParameters['Credential'])
        {
            New-PgCredential -Credential $Credential -ErrorAction Stop  | Out-Null 
            $PgCredentialInfo=Get-PgCredential 
        }
        else
        {
            $PgCredentialInfo=Get-PgCredential
            if ($PgCredentialInfo -eq $null)
            {
                New-PgCredential -ErrorAction Stop | Out-Null   
            }
        
        }
        $PgCredentialInfo=Get-PgCredential
        $Credential=$PgCredentialInfo.Credential
        [string]$PgUser=$Credential.UserName
        [string]$PgPassword=GetPlainTextPassword -SecString $Credential.Password
        if ([string]::IsNullOrEmpty($PgUser) -or [string]::IsNullOrEmpty($PgPassword))
        {
            Write-Error "Credential is null or empty" -ErrorAction Stop
        }
        $PgPathInfo=$PgCredentialInfo.PgPathInfo
        $CreateDbPath=$PgPathInfo["createdb.exe"]
        if ([string]::IsNullOrEmpty($CreateDbPath))
        {
            Write-Error "createdb.exe not found" -ErrorAction Stop
        }
        Write-Verbose "Create PgDatabase $BaseName"
        $CreateDbArgs=@(
            "-U $PgUser",
            "-w",
            "-T $Template"
            $Name
        )
        Write-Verbose "$CreateDbPath $CreateDbArgs"
        $AllDbInfo=Invoke-PgQuery  -Query  "SELECT datname from pg_database WHERE datname = '$Name'" -ReturnAs Object
        if (!($AllDbInfo.datname -eq $null))
        {
            Write-Error "$Name : database already exists" -ErrorAction Stop
        }
        $Result=InvokeExe -ExeFile $CreateDbPath -Args $CreateDbArgs -EnvVar $(@{"PGPASSWORD"=$PgPassword})
        if($Result.exitcode -ne 0)
        {
            Write-Error "ExitCode: $($Result.exitcode) StdErr: $($Result.stdErr) StdOut: $($Result.StdOut)"
        }
        else
        {
            Get-PgDatabase -Name $Name 
        }

}
function Restore-PgDatabase{
    <#
    .SYNOPSIS
        Restores a database from a backup
    .DESCRIPTION
        Restores a database from a backup
    .EXAMPLE
        Restore-PgDatabase -Name "DB1" -BackupFile С:\SQLBakup\DB1.backup
        This command will restore database "DB1" from file С:\SQLBakup\DB1.backup
    .EXAMPLE
        Get-PgDatabase | Backup-PgDatabase -Destination C:\SQLBakup\ | Restore-PgDatabase -Name {$($_.Name+"_copy")} -RemoveBackupAfterRestore
        This command will backup all databases on the server and restore with a new name 
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding(SupportsShouldProcess=$true,ConfirmImpact = 'High')]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        [string]$Name,
        [parameter(ValueFromPipelineByPropertyName=$true,Position=1)]
        [string]$BackupFile,
        [ValidateSet("Custom","Directory","Tar","Plain")]
        [string]$Format,
        [int]$Jobs,
        [switch]$RemoveBackupAfterRestore,
        [ValidateSet("template0","template1")]
        [string]$Template="template0",
        [switch]$Force,
        $Credential

    )
    
    begin
    {

        if ($PSCmdlet.MyInvocation.BoundParameters['Credential'])
        {
            New-PgCredential -Credential $Credential -ErrorAction Stop  | Out-Null 
            $PgCredentialInfo=Get-PgCredential 
        }
        else
        {
            $PgCredentialInfo=Get-PgCredential
            if ($PgCredentialInfo -eq $null)
            {
                New-PgCredential -ErrorAction Stop | Out-Null   
            }
        
        }
        $PgCredentialInfo=Get-PgCredential
        $Credential=$PgCredentialInfo.Credential
        [string]$PgUser=$Credential.UserName
        [string]$PgPassword=GetPlainTextPassword -SecString $Credential.Password
        if ([string]::IsNullOrEmpty($PgUser) -or [string]::IsNullOrEmpty($PgPassword))
        {
            Write-Error "Credential is null or empty" -ErrorAction Stop
        }
        $PgPathInfo=$PgCredentialInfo.PgPathInfo
        $PgRestorePath=$PgPathInfo["pg_restore.exe"]
        $PsqlPath=$PgPathInfo["psql.exe"]
        if ([string]::IsNullOrEmpty($PgRestorePath))
        {
            Write-Error "pg_restore.exe not found" -ErrorAction Stop
        }
        if ([string]::IsNullOrEmpty($PsqlPath))
        {
            Write-Error "psql.exe not found" -ErrorAction Stop
        }
        $FormatHashTable=@{
            "Custom"="-Fc";
            "Directory"="-Fd";
            "Tar"="-Ft";
            "Plain"="-Fp"
        }
        function SelectFile
                                                                                                                                                                                                                                                                                                                        {
        param(
            [string]$Action
        )
        [scriptblock]$SB={
            function CreateSelectFileDialog
            {
                [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
                $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
                    InitialDirectory = [Environment]::GetFolderPath('MyComputer') 
                    Filter = ''
                    Title=$Action
                }
                $null = $FileBrowser.ShowDialog()
                if ([string]::IsNullOrEmpty($FileBrowser.FileName))
                {
                    Write-Error "File not selected" -ErrorAction Stop
                }
                else
                {
                    $FileBrowser.FileName
                }    
            }
            CreateSelectFileDialog
        }
        if ([System.Threading.Thread]::CurrentThread.ApartmentState -eq "mta")
        {
            $SbStr=$SB.ToString()
            $bytes = [System.Text.Encoding]::Unicode.GetBytes($SbStr)
            $encodedCommand = [Convert]::ToBase64String($bytes)
            $Args=@(
            "-Sta"
            "-NoProfile"
            "-encodedCommand $encodedCommand"
            )
            $ArgsGetCodePage=@(
                "-Sta",
                "-NoProfile",
                "-Command [Console]::Out.Encoding.codepage"
            )
            $ResCodePage=InvokeExe -ExeFile "$Env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Args $ArgsGetCodePage
            if ($ResCodePage.ExitCode -eq 0)
            {
                $CodePage=$ResCodePage.StdOut -as [int]
                if (!($CodePage -gt 0))
                {
                    $CodePage=866
                }
            }
            else
            {
                Write-verbose "set CodePage 866" -Verbose
                 $CodePage=866
            }
       
            $Res=InvokeExe -ExeFile "$Env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Args $Args -Encoding $CodePage
            if ($Res.ExitCode -eq 0 -and !($([string]::IsNullOrEmpty($Res.StdOut))))
            {
                if (Test-Path $Res.StdOut)
                {
                    $Res.StdOut
                }
                else
                {
                    Write-Error "File not selected" -ErrorAction Stop
                }
            }
            else
            {
                Write-Error "File not selected" -ErrorAction Stop
            }
        }
        else
        {
            Invoke-Command $SB
        }
    }

        
        $ExtensionFormatHashTable=@{
            ".backup"="Custom"
            ".tar"="Tar"
            ".sql"="Plain"
        }
        $ArchiveExtension=".rar",".zip",".7zip"
    }
    process
    {
        try
        {
            if ($Name -ne $null)
            {
                if ($name.length -gt 63)
                {
                    Write-Error "The name is longer than 63 characters" -ErrorAction Stop
                }
                if ($Name -match "\s")
                {
                    Write-Error $('"'+$Name+'"'+": Name contains spaces") -ErrorAction Stop
                }
                if ($PSBoundParameters["BackupFile"] -eq $null)
                {
                    $BackupFile=SelectFile -Action "Select backup"
                }
                $MustBeRemoved=$false
                $BackupFileObj=Get-Item $BackupFile -ErrorAction Stop
                $FileExtension=$BackupFileObj.Extension
    
                if ($ArchiveExtension -eq $FileExtension)
                {
        
                    $FileExtension=$BackupFileObj.Extension
                    if ($ArchiveExtension -eq $FileExtension)
                    {
           
                        if ($BackupFileObj.Name -match "^(.+)_(.+)_([\d]{4})_([\d]{2})_([\d]{2})_([\d]{2})([\d]{2})([\d]{2}).*\.(.+)$")
                        {
                            $DestinationArchive= Join-Path $BackupFileObj.Directory -ChildPath "Tmp"
                            Write-Verbose "Decompress-Archive -Path $BackupFile -DestinationPath $DestinationArchive" -Verbose
                            $DecompressBackup=Decompress-Archive -Path $BackupFile -DestinationPath $DestinationArchive 
                            $MustBeRemoved=$true
                            $TmpBackupFileObj=Get-ChildItem -Path $DecompressBackup.fullName -ErrorAction Stop | Where-Object {$_.BaseName -eq $BackupFileObj.BaseName -and $_.Extension -ne ".log"}
                            $TmpBackupFileObj=Get-Item -Path $TmpBackupFileObj.fullName -ErrorAction Stop
                            $BackupFileObj=$TmpBackupFileObj
                            $FileExtension=$BackupFileObj.Extension    
                
                
                        }
                        else
                        {
                            Write-Error "$BackupFile :Incorrect name format. Unzip the archive and try again" -ErrorAction Stop
                        }


        
                    }
                }
                $RestoreTableFromBin=$false
                if ($BackupFileObj.PSIsContainer)
                {
                    
                    $Format="Directory"
                    [array]$BinBackups=Get-ChildItem $BackupFileObj.FullName | Where-Object {$_.Name -match "$($BackupFileObj.BaseName)_.+\.bin"}
                    
                }
                else
                {
        
                    if ($PSBoundParameters["Format"] -eq $null)
                    {
            
                        $FormatTmp=$ExtensionFormatHashTable[$FileExtension]
            
                        if ([string]::IsNullOrEmpty($FormatTmp))
                        {

                            Write-Error "$BackupFile Unknown backup format. To set the backup format, use the -Format parameter" -ErrorAction Stop
                        }
                        else
                        {
                            
                            $Format=$FormatTmp 
                            [array]$BinBackups=Get-ChildItem $BackupFileObj.DirectoryName | Where-Object {$_.Name -match "$($BackupFileObj.BaseName)_.+\.bin"}
 
                            
                        }
                    }
                }
                if ($BinBackups)
                {
                    $RestoreTableFromBin=$true    
                }
                Write-Verbose "Backup format defined as:$Format Database:$Name Starting restore process please wait.." -Verbose

                $DatabaseExist=$true
                if ($(Invoke-PgQuery -Query  "SELECT datname from pg_database Where datname='$Name'"  -ErrorAction Stop) -eq $null)
                {
                    $DatabaseExist=$false
                }
                $RecoveryName=$Name+"_in_a_state_of_recovery"
                $DbRecovery=$null
                $DbRecovery=Invoke-PgQuery -Query  "SELECT datname from pg_database Where datname='$RecoveryName'"  -ErrorAction Stop
    
                if ($DatabaseExist)
                {
        
                    if ($PSCmdlet.ShouldProcess($Name,"Remove-PgDatabase"))
                    {
                        Remove-PgDatabase -Name $Name -Force:$($PSBoundParameters["Force"].IsPresent) -Verbose:$false -Confirm:$false  -ErrorAction Stop
                    }
                    else
                    {
                        Write-Error "To continue, you need to delete the $Name database" -ErrorAction Stop
                    }    
          
                }
                if($DbRecovery -ne $null)
                {
                    Remove-PgDatabase -Name $RecoveryName  -Force
                }

                New-PgDatabase -Name $RecoveryName -Template $Template  -ErrorAction Stop  | Out-Null
    
   
                $AllowJobsFormat="Directory","Custom"
                if ($AllowJobsFormat -eq $Format)
                {
                    if ($PSBoundParameters["Jobs"])
                    {
                        $LogicalProcessorsCount=GetLogicalProcessorsCount
                        if (!($Jobs -gt 0 -and $Jobs -le $LogicalProcessorsCount))
                        {
                            Write-Verbose "The value of the -Jobs parameter must be in the range [1 - $LogicalProcessorsCount]. Set -Jobs $LogicalProcessorsCount" -Verbose
                            $Jobs=$LogicalProcessorsCount
                        }
                    }
                    else
                    {
                        $Jobs=1
                    }
                }
                elseif($PSBoundParameters["Jobs"])
                {
                    Write-Verbose "The -Jobs parameter was ignored. This option is only supported for the format $AllowJobsFormat" -Verbose
                }
                $RestoreBackupFile='"'+$($BackupFileObj.fullname)+'"'
                $PgRestoreArgs=$null
                $PgAppPath=$null
                if ($Format -eq "Plain" -or $Format -eq "CompressPlain")
                {
                    $PgAppPath=$PsqlPath
                    $PgRestoreArgs=@(
                       "-U $PgUser",
                       "-w",
                       "-d $RecoveryName",
                       $("--file="+$RestoreBackupFile) 
                    )
                    if ($PSBoundParameters["Verbose"].IsPresent)
                    {
                        $PgRestoreArgs+="--echo-all"
                    }
                }
                else
                {
                    $PgAppPath=$PgRestorePath
                    $PgRestoreArgs=@(
                       "-U $PgUser",
                       "-w",
                       "--role $PgUser",
                       $FormatHashTable[$Format],
                       "--if-exists",
                       "-c",
                       "-d $RecoveryName"
           
                    )
                    if ($PSBoundParameters["Verbose"].IsPresent)
                    {
                        $PgRestoreArgs+="--verbose"
                    }
                    if ($AllowJobsFormat -eq $Format)
                    {
                        $PgRestoreArgs+="--jobs=$Jobs"
                    }
                    $PgRestoreArgs+="$RestoreBackupFile"
                }
                Write-Verbose "$PgAppPath $PgRestoreArgs"
                Write-Verbose "$RecoveryName :Restoring from file $RestoreBackupFile Please wait.." -Verbose
                Write-Verbose "$PgAppPath $PgRestoreArgs"
                $Result=InvokeExe -ExeFile $PgAppPath -Args $PgRestoreArgs -EnvVar $(@{"PGPASSWORD"=$PgPassword}) -ErrorAction Stop -VerboseOutput:$($PSBoundParameters["Verbose"].IsPresent)   
                Write-Verbose "ExitCode: $($Result.exitcode) StdErr: $($Result.stdErr)"
                if ($Result.ExitCode -eq 0)
                {
                    if ($RestoreTableFromBin)
                    {
                        if ($BinBackups.Count -gt 0){
                            $BinBackups | foreach {
                                $BinBackup=$_
                                $BinBackupPath=$_.FullName
                                if ($BinBackup -match ".+\d{6}_(.+)\.bin$"){
                                    $TableName=$Matches[1]
                                }else{
                                    Write-Error "Incorrect file name $BinBackup.fullname" -ErrorAction Stop
                                }
                            
                                Write-Verbose "$RecoveryName :Restore public.$TableName from file $BinBackupPath" -Verbose
                                $RestoreTableQuery="\COPY public.$TableName FROM "+"'"+$($BinBackupPath -replace "\\","\\")+"'"+"  WITH BINARY;"
                                Invoke-PgQuery -Name $RecoveryName -Query $RestoreTableQuery -ReturnAs Raw -ErrorAction Stop | Out-Null 
                            }
                        }
                        
                    }
                    Write-Verbose "$RecoveryName Success restored from backup $BackupFile"
                    if ($Name -ne $RecoveryName)
                    {
                        Write-Verbose "Rename-PgDatabase -Name $RecoveryName -NewName $Name"
                        Rename-PgDatabase -Name $RecoveryName -NewName $Name -Confirm:$false -Verbose:$false -ErrorAction Stop | Out-Null
                        Write-Verbose "$Name :All recovery operations completed successfully. The database was restored from a file $BackupFile" -Verbose
                    }
                    Get-PgDatabase -Name $Name -Verbose:$false
                    if ($PSBoundParameters["RemoveBackupAfterRestore"].isPresent)
                    {
                        Remove-Item -Path $BackupFile -Recurse -Force 
                    }
        
                }
                else
                {
                    Write-Verbose "Remove-PgDatabase -Name $RecoveryName" -Verbose
                    Remove-PgDatabase -Name $RecoveryName -Confirm:$false -Force
                    Write-Error "ExitCode: $($Result.exitcode) StdErr: $($Result.stdErr) StdOut: $($Result.StdOut)"

                }
                if ($MustBeRemoved)
                {
                    Remove-Item -Path $DestinationArchive -Recurse -Force
                }
            }
        }
        catch
        {
            Write-Error $_
        }
    
    }
    end
    {
    
    }
    
}
function Backup-PgDatabase{
    <#
    .SYNOPSIS
        Makes a database backup
    .DESCRIPTION
        Makes a database backup
    .EXAMPLE
        Get-PgDatabase | Backup-PgDatabase -Destination C:\SQLBakup\
        This command creates a database backup of the all databases on the server to the directory C:\SQLBakup\
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        [string]$Name,
        [string]$Destination,
        [ValidateSet("Custom","CompressCustom","Directory","CompressDirectory","Tar","Plain","CompressPlain")]
        [string]$Format="Custom",
        [ValidateScript({-not ($_ -match "\s+")})]
        [string[]]$SaveTableAsBinary,
        [int]$Jobs,
        [switch]$CreateLog,
        $Credential
    )
    begin
    {
        
        if ($name.length -gt 63)
        {
            Write-Error "The name is longer than 63 characters" -ErrorAction Stop
        }
        function GetFolder
        {
            $app = new-object -com Shell.Application -ErrorAction Stop
            $folder = $app.BrowseForFolder(0, "Select Folder", 0)
            if (!([string]::IsNullOrEmpty($folder.Self.Path))) 
            {
               $folder.Self.Path
            }
            else
            {
                Write-Error "Folder not selected" -ErrorAction Stop
            }   
        }
        
        if ($PSBoundParameters["Destination"] -eq $null)
        {
            $SelectedDestination=GetFolder
            $Destination=$SelectedDestination
            Write-Verbose "Selected $SelectedDestination"
        }
        else
        {
            $SelectedDestination=$Destination
        }
        
        $AllowJobsFormat="Directory","CompressDirectory"
        if ($AllowJobsFormat -eq $Format)
        {
            if ($PSBoundParameters["Jobs"])
            {
                $LogicalProcessorsCount=GetLogicalProcessorsCount
                if (!($Jobs -gt 0 -and $Jobs -le $LogicalProcessorsCount))
                {
                    Write-Verbose "The value of the -Jobs parameter must be in the range [1 - $LogicalProcessorsCount]. Set -Jobs $LogicalProcessorsCount" -Verbose
                    $Jobs=$LogicalProcessorsCount
                }
            }
            else
            {
                $Jobs=1
            }
        }
        elseif($PSBoundParameters["Jobs"])
        {
            Write-Verbose "The -Jobs parameter was ignored. This option is only supported for the format $AllowJobsFormat" -Verbose
        }
        if ($PSCmdlet.MyInvocation.BoundParameters['Credential'])
        {
            New-PgCredential -Credential $Credential -ErrorAction Stop  | Out-Null 
            $PgCredentialInfo=Get-PgCredential 
        }
        else
        {
            $PgCredentialInfo=Get-PgCredential
            if ($PgCredentialInfo -eq $null)
            {
                New-PgCredential -ErrorAction Stop | Out-Null   
            }
        
        }
        $PgCredentialInfo=Get-PgCredential
        $Credential=$PgCredentialInfo.Credential
        [string]$PgUser=$Credential.UserName
        [string]$PgPassword=GetPlainTextPassword -SecString $Credential.Password
        if ([string]::IsNullOrEmpty($PgUser) -or [string]::IsNullOrEmpty($PgPassword))
        {
            Write-Error "Credential is null or empty" -ErrorAction Stop
        }
        
        $PgPathInfo=$PgCredentialInfo.PgPathInfo
        $PgAppPath=$PgPathInfo["pg_dump.exe"]
        if ([string]::IsNullOrEmpty($PgAppPath))
        {
            Write-Error "pg_dump.exe not found" -ErrorAction Stop
        }
        $FormatHashTable=@{
            "Custom"="-Fc";
            "CompressCustom"="-Fc"
            "Directory"="-Fd";
            "CompressDirectory"="-Fd"
            "Tar"="-Ft";
            "Plain"="-Fp"
        }
        if ([string]::IsNullOrEmpty($Destination))
        {
            Write-Error "Destination is null or empty" -ErrorAction Stop
        }
        
        if (!((Get-Item -Path $Destination -ErrorAction Stop).PSIsContainer))
        {
            Write-Error "Incorrect path $Destination Destination must be directory!" -ErrorAction Stop
        }


    }
    process
    {
        try
        {
            if ($Name -ne $null)
            {
                
                $Destination=$SelectedDestination
                if ($name.length -gt 63)
                {
                    Write-Error "The name is longer than 63 characters" -ErrorAction Stop
                }
                $BeginFunction=get-date
                $FileDate=Get-Date -Format yyyy_MM_dd_HHmmss
                $BackupFileNameBin=$Name+"_backup_"+$FileDate
                $BackupFileName=$Name+"_backup_"+$FileDate
                $LogFileName=$BackupFileName+".log"
                if ($Format -eq "Custom" -or $Format -eq "CompressCustom")
                {
                    $BackupFileName+=".backup"
                }
                if ($Format -eq "Plain" -or $Format -eq "CompressPlain")
                {
                    $BackupFileName+=".sql"
                }
                if ($Format -eq "Tar")
                {
                    $BackupFileName+=".tar"
                }
                $DestinationFullPath=Join-Path -Path $Destination -ChildPath $BackupFileName
                $DestinationLogPath=$null
                if ($PSBoundParameters["CreateLog"].isPresent)
                {
                    $DestinationLogPath=Join-Path -Path $Destination -ChildPath $LogFileName     
                }
                
                $PgArg=$null
                $PgArg=@(
                    "-U $PgUser",
                    "-w",
                    "-d $Name",
                    "--blobs",
                    $("--file="+'"'+$DestinationFullPath+'"')
                )
                [string[]]$SaveAsBinary=@()
                if ($PSBoundParameters['SaveTableAsBinary'].Count -gt 0){
                   $SaveAsBinary+=$SaveTableAsBinary
                }
                
                #This code is associated with the commercial software package 1C:Enterprise. You can remove this part of the code if you don't need it.
                
                $LargeBinaryStringIn1cTable=$False
                function Check1cTable{
                    [cmdletbinding()]
                    param(
                        [string]$DbName
                    )
                    [int32]$MaxBinaryStringSize="523239424"
                    try{
                        $Check1cTable=@{
                            "config"=@("binarydata")
                            "_systemsettings"=@("_settingsdata")
                        }
                        $LargeTables=@()
                        $Check1cTable.Keys | foreach {
                            $TableName=$_
                            [string[]]$Columns=$Check1cTable[$TableName]
                            $Columns | foreach {
                                [string]$Column=$_
                                $Query="select octet_length($Column) as "+'"octet_length"'+ " from $TableName order by octet_length desc limit 1"
                                Write-Verbose "Invoke-PgQuery -Query $Query -Name $DbName"
                                $BinarySizeInDB=(((Invoke-PgQuery -Query $Query -Name $DbName -ErrorAction Stop).octet_length -as [int64]))   
                                if ($BinarySizeInDB -gt $MaxBinaryStringSize){
                                    if (-not ($LargeTables -eq $TableName)){
                                        $LargeTables+=$TableName
                                    }
          
                                }
                    
                                Write-Verbose "$TableName : $Column : size $($BinarySizeInDB/1mb)Mb" 
                            }
            

        
                        }
                        $LargeTables
        
        
                    }
                    catch
                    {
                        Write-Verbose "$_"
                    }    
                }
                [string[]]$Large1cTable=Check1cTable -DbName $Name
                if($Large1cTable.Count -gt 0){
                    Write-Verbose "$($Name): One of the table entries is large. Read more https://infostart.ru/1c/articles/956734/" -Verbose
                    $LargeBinaryStringIn1cTable=$true
                    $SaveAsBinary+=$Large1cTable
                    
                }
                ##End code associated with the commercial software package 1C:Enterprise.
                
                [string[]]$SaveAsBinary=$SaveAsBinary | Select-Object -Unique
                #Write-Debug -Message "dbg" -Debug
                if ($SaveAsBinary.Count -gt 0)
                {
                    Write-Verbose "$Name :Multiple backup files will be created."
                    [string[]]$DestinationBinaryPaths=@()
                    $SaveAsBinary | foreach {
                        $TableName=$_
                        if ($TableName -match "^public\."){
                            $TableName=$TableName -replace "public\."
                        }
                        $BackupFileNameBinary=$BackupFileNameBin+"_"+$TableName+".bin"
                        $DestinationBinaryPath=Join-Path -Path $Destination -ChildPath $BackupFileNameBinary
                        $CopyConfigQuery="\COPY public.$TableName TO "+"'"+$($DestinationBinaryPath -replace "\\","\\")+"'"+" WITH BINARY;"
                        Write-Verbose "$($Name+':') Backup table public.$TableName to file $DestinationBinaryPath Please wait.." -Verbose
                        Invoke-PgQuery -Query $CopyConfigQuery -Name $Name -ReturnAs Raw -ErrorAction Stop | Out-Null
                        $PgArg+="--exclude-table-data=public.$TableName"
                        $DestinationBinaryPaths+=$DestinationBinaryPath
                    }
                        
                }

                  
                
                $DumpFormat=$FormatHashTable[$Format]
                if ($DumpFormat -eq "-Fd")
                {
                    $PgArg+="--jobs=$Jobs"
                }
                $PgArg+=$DumpFormat
                
                $VerboseOutput=$False
                if ($PSBoundParameters["Verbose"].IsPresent -or $PSBoundParameters["CreateLog"].isPresent)
                {
                    $PgArg+="--verbose"
                    if($PSBoundParameters["Verbose"].IsPresent)
                    {
                        $VerboseOutput=$true    
                    }
                
                }
                Write-Verbose "$($Name+':') Starting backup to file $DestinationFullPath " -Verbose
                Write-Verbose "$($Name+':') Backup in progress. Please wait.." -Verbose
                write-verbose $($('"'+$PgAppPath+'"')+" $PgArg")
                $Result=InvokeExe -ExeFile $PgAppPath -Args $PgArg -EnvVar $(@{"PGPASSWORD"=$PgPassword}) -VerboseOutput:$VerboseOutput -LogPath $DestinationLogPath
                Write-Verbose "ExitCode: $($Result.exitcode) StdErr: $($Result.stdErr)"
                $OutRes=New-Object -TypeName psobject
                $OutRes | Add-Member -MemberType NoteProperty -Name Name -Value $Name
                $OutRes | Add-Member -MemberType NoteProperty -Name Format -Value $Format
                $OutRes | Add-Member -MemberType NoteProperty -Name BackupFile -Value $DestinationFullPath
                if ($PSBoundParameters["CreateLog"].isPresent)
                {
                    $OutRes | Add-Member -MemberType NoteProperty -Name LogFile -Value $DestinationLogPath    
                }
                else
                {
                    $OutRes | Add-Member -MemberType NoteProperty -Name LogFile -Value $null
                }
            
                $OutRes | Add-Member -MemberType NoteProperty -Name Size -Value 0
                $OutRes | Add-Member -MemberType NoteProperty -Name BackupTime -Value 0
                #$OutRes | Add-Member -MemberType NoteProperty -Name ExitCode -Value $Result.exitcode
                #$OutRes | Add-Member -MemberType NoteProperty -Name StdOut -Value $Result.stdout
                #$OutRes | Add-Member -MemberType NoteProperty -Name StdErr -Value $Result.stderr
                if ($Result.exitcode -eq 0)
                {
                    if ($($Format -eq "Directory" -or $Format -eq "CompressDirectory") -and $($DestinationBinaryPaths.Count -gt 0))
                    {
                        $DestinationBinaryPaths | foreach {
                            $DestinationBinaryPath=$_
                            Move-Item -Path $DestinationBinaryPath -Destination $DestinationFullPath -Confirm:$False    
                        }
                    }
                    if ($PSBoundParameters["Format"] -eq "CompressDirectory")
                    {
                        $CompressFiles=@()
                        $CompressFiles+=$($OutRes.BackupFile)
                        if (!([string]::IsNullOrEmpty($($OutRes.LogFile))))
                        {
                            $CompressFiles+=$($OutRes.LogFile)
                        }
                        Write-Verbose "$($Name+':') Backup success. Compress7zip -Path $CompressFiles -NoCompression -DelAfterCompress" -Verbose
                        $CompressedDumpPath=Compress7zip -Path $CompressFiles -NoCompression -DelAfterCompress -Type zip -ErrorAction Stop
                        $OutRes.BackupFile=$CompressedDumpPath
                        if (!([string]::IsNullOrEmpty($OutRes.LogFile)))
                        {
                            $OutRes.Logfile=$CompressedDumpPath   
                        }
                    
                    }
                    if ($PSBoundParameters["Format"] -eq "CompressPlain" -or $PSBoundParameters["Format"] -eq "CompressCustom")
                    {
                        $CompressFiles=@()
                        $CompressFiles+=$($OutRes.BackupFile)
                        #Write-Debug -Message dbg -Debug
                        if ($DestinationBinaryPaths.Count -gt 0){
                            $CompressFiles+=$DestinationBinaryPaths
                        }
                        if (!([string]::IsNullOrEmpty($($OutRes.LogFile))))
                        {
                            $CompressFiles+=$($OutRes.LogFile)
                        }
                        
                        Write-Verbose "$($Name+':') Backup success. Compress7zip -Path $CompressFiles -DelAfterCompress" -Verbose
                        if($PSBoundParameters["Format"] -eq "CompressCustom"){
                            $CompressedDumpPath=Compress7zip -Path $CompressFiles -DelAfterCompress -Type zip  -NoCompression -ErrorAction Stop
                        }else{
                            $CompressedDumpPath=Compress7zip -Path $CompressFiles -DelAfterCompress -Type zip -ErrorAction Stop
                        }
                        
                        $OutRes.BackupFile=$CompressedDumpPath
                        if (!([string]::IsNullOrEmpty($OutRes.LogFile)))
                        {
                            $OutRes.Logfile=$CompressedDumpPath   
                        }
                    }
                    $DumpSize=(Get-ChildItem $OutRes.BackupFile | Measure-Object Length -s).sum
                    $RunningTime=New-TimeSpan -Start $BeginFunction
                    if ($DumpSize -ne 0)
                    {
                       #$RunnningTime=[timespan]::FromSeconds($RunningTime)
                       $OutRes.Size=$DumpSize
                       $OutRes.BackupTime= $RunningTime
                       $OutRes.psobject.typenames.insert(0,"ModulePostgresCmdlets.PostgresCmdlets.Database.Backup")
                       $OutRes 
                    }
                    else
                    {
                        Write-Error "$($OutRes.BackupFile) incorrect file size"
                    }    
                }
                else
                {
                    Write-Error "ExitCode: $($Result.exitcode) StdErr: $($Result.stdErr) StdOut: $($Result.StdOut)"
                }
            
                          
            }
        }
        catch
        {
            Write-Error $_
        }
        
        
    }
    end
    {
            Write-Verbose  "End Backup Backup-PgDatabase"
    }

}
function Disable-PgDatabaseConnections{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        [string]$Name,
        [switch]$NotCloseConnections,
        [switch]$AllowOnlySuperUser,
        $Credential
    )
    begin
    {
        if ($PSCmdlet.MyInvocation.BoundParameters['Credential'])
        {
            New-PgCredential -Credential $Credential  -ErrorAction Stop  | Out-Null 
            $PgCredentialInfo=Get-PgCredential 
        }
        else
        {
            $PgCredentialInfo=Get-PgCredential
            if ($PgCredentialInfo -eq $null)
            {
                New-PgCredential -ErrorAction Stop | Out-Null   
            }
        
        }
        $PgCredentialInfo=Get-PgCredential
        $Credential=$PgCredentialInfo.Credential
        [string]$PgUser=$Credential.UserName
        [string]$PgPassword=GetPlainTextPassword -SecString $Credential.Password
        if ([string]::IsNullOrEmpty($PgUser) -or [string]::IsNullOrEmpty($PgPassword))
        {
            Write-Error "Credential is null or empty" -ErrorAction Stop
        }
    }
    process
    {
        if (!([string]::IsNullOrEmpty($Name)))
        {

            
            $AllDbInfo=Invoke-PgQuery  -Query  "SELECT datname,datallowconn,datconnlimit from pg_database WHERE datname = '$Name'" -ReturnAs Object
            if ($AllDbInfo.datname -eq $null)
            {
                Write-Error "$Name not found"
            }
            else
            {
                if ($PSBoundParameters["AllowOnlySuperUser"].IsPresent)
                {
                    $SetConLimitQuery="ALTER DATABASE "+'\"'+$Name+'\"'+" CONNECTION LIMIT 0"
                    Invoke-PgQuery -Query $SetConLimitQuery -ReturnAs Raw | Out-Null
                    if($AllDbInfo.datallowconn -eq $false)
                    {
                        Invoke-PgQuery -Query "UPDATE pg_database SET datallowconn = true WHERE datname = '$Name'"  -ReturnAs Raw | Out-Null    
                    }
                    
                }
                else
                {
                    if ($AllDbInfo.datallowconn -eq $true)
                    {
                        Write-Verbose "$Name :Disable connection"
                        Invoke-PgQuery -Query "UPDATE pg_database SET datallowconn = false WHERE datname = '$Name'"  -ReturnAs Raw | Out-Null
                    
                    }
                    elseif($AllDbInfo.datallowconn -eq $false)
                    {
                        Write-Verbose "$Name :Connections have already been denied "
                        if ($AllDbInfo.datconnlimit -eq 0)
                        {
                            #Invoke-PgQuery -Query "ALTER DATABASE $Name CONNECTION LIMIT -1" -ReturnAs Raw  | Out-Null
                            
                        }
                    }
                    else
                    {
                        Write-Error "datallowconn must be $true or $false "
                    }    
                }
                
                if (!($PSBoundParameters["NotCloseConnections"].isPresent))
                {
                    
                    $Connections=@()
                    [array]$AllConnections=Invoke-PgQuery -Query  "SELECT datname FROM pg_stat_activity Where datname='$Name'" 
                    if ($AllConnections -ne $null)
                    {
                        $Connections+=$AllConnections
                    }
                    Write-Verbose "$($Connections.count) connections open"
                    if ($Connections.Count -ne 0)
                    {
                        [array]$CloseConnections=Invoke-PgQuery -Query "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$Name'" 
                        Write-Verbose "Succesfully closed $($CloseConnections.count) connections"
                    }
                    
                }
                
                $DbRes=Get-PgDatabase -Name $Name 
                if($DbRes.AllowConn -eq $true)
                {
                    if (!($PSBoundParameters["AllowOnlySuperUser"].IsPresent))
                    {
                        Write-Error "$Name :An error occurred while changing datallowconn"
                    }
                    else
                    {
                         $DbRes
                    }
                    
                }
                else
                {
                    if (!($PSBoundParameters["NotCloseConnections"].isPresent) -and $DbRes.ConnectionCount -ne 0 -and !($PSBoundParameters["AllowOnlySuperUser"].IsPresent))
                    {
                        Write-Error "$Name :Failed to close connections"
                    }
                    else
                    {
                        $DbRes
                    }
                }
                
            }
            
            
        }
        
    }
    end
    {
    
    }
}
function Enable-PgDatabaseConnections{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        [string]$Name,
        [switch]$AllowOnlySuperUser,
        $Credential
    )
    begin
    {
        if ($PSCmdlet.MyInvocation.BoundParameters['Credential'])
        {
            New-PgCredential -Credential $Credential  -ErrorAction Stop  | Out-Null 
            $PgCredentialInfo=Get-PgCredential 
        }
        else
        {
            $PgCredentialInfo=Get-PgCredential
            if ($PgCredentialInfo -eq $null)
            {
                New-PgCredential -ErrorAction Stop | Out-Null   
            }
        
        }
        $PgCredentialInfo=Get-PgCredential
        $Credential=$PgCredentialInfo.Credential
        [string]$PgUser=$Credential.UserName
        [string]$PgPassword=GetPlainTextPassword -SecString $Credential.Password
        if ([string]::IsNullOrEmpty($PgUser) -or [string]::IsNullOrEmpty($PgPassword))
        {
            Write-Error "Credential is null or empty" -ErrorAction Stop
        }
    }
    process
    {
        if (!([string]::IsNullOrEmpty($Name)))
        {

            $AllDbInfo=Invoke-PgQuery  -Query  "SELECT datname,datallowconn,datconnlimit from pg_database WHERE datname = '$Name'" -ReturnAs Object
            if ($AllDbInfo.datname -eq $null)
            {
                Write-Error "$Name not found"
            }
            else
            {
                if ($AllDbInfo.datallowconn -eq $false)
                {
                    Write-Verbose "$Name :Enable connection"
                    Invoke-PgQuery -Query "UPDATE pg_database SET datallowconn = true WHERE datname = '$Name'" -ReturnAs Raw   | Out-Null
                    
                }
                elseif($AllDbInfo.datallowconn -eq $true)
                {
                    Write-Verbose "$Name :Connections have already been enabled"
                }
                else
                {
                    Write-Error "datallowconn must be $true or $false "
                }
                if ($AllDbInfo.datconnlimit -eq 0 -and !($PSBoundParameters["AllowOnlySuperUser"]))
                {
                    $SetConLimitQuery="ALTER DATABASE "+'\"'+$Name+'\"'+" CONNECTION LIMIT -1"
                    Invoke-PgQuery -Query $SetConLimitQuery -ReturnAs Raw  | Out-Null
                }
                if ($PSBoundParameters["AllowOnlySuperUser"])
                {
                    $SetConLimitQuery="ALTER DATABASE "+'\"'+$Name+'\"'+" CONNECTION LIMIT 0"
                    Invoke-PgQuery -Query $SetConLimitQuery -ReturnAs Raw  | Out-Null
                }
                $DbRes=Get-PgDatabase -Name $Name 
                if($DbRes.AllowConn -eq $false)
                {
                    Write-Error "$Name :An error occurred while changing datallowconn"
                }
                else
                {  
                    $DbRes
                }
                
            }
            
            
        }
        
    }
    end
    {
    
    }
}
function Rename-PgDatabase{
    <#
    .SYNOPSIS
        Renames the database
    .DESCRIPTION
        Renames the database
    .EXAMPLE
        Get-PgDatabase | Rename-PgDatabase -NewName {$($_.name+"_tmp")} -Confirm:$false
        This command will rename all databases on the server by adding "_tmp" to the old name
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding(SupportsShouldProcess=$true,ConfirmImpact = 'High')]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        [string]$Name,
        [parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,Position=1)]
        [string]$NewName,
        $Credential

    )
    begin
    {
        if ($PSCmdlet.MyInvocation.BoundParameters['Credential'])
        {
            New-PgCredential -Credential $Credential  -ErrorAction Stop  | Out-Null 
            $PgCredentialInfo=Get-PgCredential 
        }
        else
        {
            $PgCredentialInfo=Get-PgCredential
            if ($PgCredentialInfo -eq $null)
            {
                New-PgCredential -ErrorAction Stop | Out-Null   
            }
        
        }
        $PgCredentialInfo=Get-PgCredential
        $Credential=$PgCredentialInfo.Credential
        [string]$PgUser=$Credential.UserName
        [string]$PgPassword=GetPlainTextPassword -SecString $Credential.Password
        if ([string]::IsNullOrEmpty($PgUser) -or [string]::IsNullOrEmpty($PgPassword))
        {
            Write-Error "Credential is null or empty" -ErrorAction Stop
        }
    }
    process
    {
        if (!([string]::IsNullOrEmpty($Name)) -and !([string]::IsNullOrEmpty($NewName)))
        {
            try
            {
                if ($NewName -match "\s")
                {
                    Write-Error "New name contains spaces" -ErrorAction Stop
                }
                if ($Name.length -gt 63 -or $NewName.Length -gt 63)
                {
                    Write-Error "The Name -or NewName is longer than 63 characters" -ErrorAction Stop
                }
                if ($Name -eq $NewName)
                {
                    Write-Error "Name and NewName name must be different" -ErrorAction Stop
                }
                else
                {
                    $DatabaseInfo=Get-PgDatabase -Name $Name  -ErrorAction Stop
                    $NewDbInfo=Invoke-PgQuery  -Query  "SELECT datname from pg_database WHERE datname = '$NewName'" -ReturnAs Object
                    if (!($NewDbInfo.datname -eq $null))
                    {
                        Write-Error "database $NewName already exists" -ErrorAction Stop
                    }
                    if ($PSCmdlet.ShouldProcess("Database: $Name New name: $NewName"))
                    {
                    
                    
                        $OldNameAllowConn=$DatabaseInfo.AllowConn

                        $Res=Disable-PgDatabaseConnections -Name $Name  -ErrorAction Continue
                        if ($Res.AllowConn -eq $false -and $Res.ConnectionCount -eq 0)
                        {
                            $QueryRename="ALTER DATABASE "+'\"'+$Name+'\"'+" RENAME TO "+'\"'+$NewName+'\"'
                            Invoke-PgQuery -Query $QueryRename -ReturnAs Raw  -ErrorAction Stop | Out-Null
                            $NewNameDatabase=Invoke-PgQuery  -Query  "SELECT datname,datallowconn from pg_database WHERE datname = '$NewName'" -ReturnAs Object
                            if ($NewNameDatabase.AllowConn -ne $OldNameAllowConn)
                            {
                                Invoke-PgQuery -Query "UPDATE pg_database SET datallowconn = $OldNameAllowConn WHERE datname = '$NewName'" -ReturnAs Raw  -ErrorAction Stop | Out-Null
                            }
                            Get-PgDatabase -Name $NewName  -ErrorAction Stop

                        }
                        else
                        {
                            Write-Error "Failed to deny or close database connections" -ErrorAction Stop
                        }
                    }          
                
                  
                }
            
            }
            catch
            {
                Write-Error "$Name NewName: $NewName : $_"
            }

        }

    }
    end
    {
    
    }
}
function New-PgCredential{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    Param(
        $Credential,
        [switch]$SaveCredential
    )
        
        function CreateCredential
        {
            [cmdletbinding()]
            param(
                [parameter(Mandatory=$true)]
                [string]$User,
                [string]$Password
            )
    
            Write-Verbose "Create Credential User $User, Password $password"
    
            if ($PSBoundParameters["Password"])
            {
                $SecPassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
                $Credential = New-Object System.Management.Automation.PSCredential($User,$SecPassword)  
            }
            else
            {
                $Credential = New-Object System.Management.Automation.PSCredential($User,(new-object System.Security.SecureString))
            }
    
    
            $Credential
        }
        if ($PSCmdlet.MyInvocation.BoundParameters['Credential'])
        {
            if (!($Credential.gettype().name -eq "PSCredential"))
            {
                $Credential=Get-Credential $Credential -ErrorAction Stop
            }    
        }
        else
        {
            $Credential=Get-Credential "postgres"  -ErrorAction Stop
        }
        if ($Credential)
        {
            [string]$PgUser=$Credential.UserName
            if ($PgUser -match "^\\")
            {
                $PgUser=$PgUser -replace "^\\"
            }
            [string]$PgPassword=GetPlainTextPassword -SecString $Credential.Password
            if ([string]::IsNullOrEmpty($PgUser) -or [string]::IsNullOrEmpty($PgPassword))
            {
                Write-Error "Credential is null or empty" -ErrorAction Stop
            }
        }
        else
        {
            Write-Error "Credential is null or empty" -ErrorAction Stop
        }
        
        $Credential=CreateCredential -User $PgUser -Password $PgPassword -ErrorAction Stop
        $PgPathInfo=GetPgAppPaths -AppNames "psql.exe","dropdb.exe","createdb.exe","pg_restore.exe","pg_dump.exe","vacuumdb.exe"
        $PgInfoObject=New-Object -TypeName psobject
        $PgInfoObject | Add-Member -MemberType NoteProperty -Name Credential -Value $Credential
        $PgInfoObject | Add-Member -MemberType NoteProperty -Name PgPathInfo -Value $PgPathInfo
        try
        {
            $PgCredVar=Get-Variable -Name PostgresCmdletsCredential -ErrorAction Stop
            Set-Variable -Name  PostgresCmdletsCredential -Value $PgInfoObject -Visibility Private -Scope Global
        }
        catch
        {
            New-Variable -Name PostgresCmdletsCredential -Value $PgInfoObject -Visibility Private -Scope Global -ErrorAction Stop
        }
        if ($PSBoundParameters["SaveCredential"].isPresent)
        {
            $SavePath="HKCU:\Software\PsCred"
            $SavePathPg=Join-Path -Path $SavePath -ChildPath Postgres
            if (!(Test-Path $SavePathPg))
            {
                if (!(Test-Path $SavePath))
                {
                    New-Item -Path $SavePath -ErrorAction Stop | Out-Null
                    New-Item -Path $SavePathPg -ErrorAction Stop | Out-Null
                }
                elseif(!(Test-Path $SavePathPg))
                {
                    New-Item -Path $SavePathPg -ErrorAction Stop | Out-Null
                }
            }
            Remove-ItemProperty -Path $SavePathPg -Name UserName -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $SavePathPg -Name SecPass -ErrorAction SilentlyContinue
            $SecPass=ConvertFrom-SecureString $Credential.password
            New-ItemProperty -Path $SavePathPg -Name UserName -Value $Credential.UserName -PropertyType String -ErrorAction Stop | Out-Null 
            New-ItemProperty -Path $SavePathPg -Name SecPass -Value $SecPass -PropertyType String -ErrorAction Stop | Out-Null
        }
        Get-Variable -Name PostgresCmdletsCredential -ValueOnly
}
function Get-PgCredential{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    Param()
        $PgCred=$null
        try
        {
            $PgCred=Get-Variable -Name PostgresCmdletsCredential -ValueOnly -ErrorAction Stop

        }
        catch
        {
            Write-Verbose "$_"
        }
        if ($PgCred)
        {
            $PgCred
        }
        else
        {
            $PgSavePath="HKCU:\Software\PsCred\Postgres"
            $PgUser=(Get-ItemProperty -Path $PgSavePath -Name UserName -ErrorAction SilentlyContinue).UserName 
            $PgSecPass=(Get-ItemProperty -Path $PgSavePath -Name SecPass -ErrorAction SilentlyContinue).SecPass
            if (!([string]::IsNullOrEmpty($Pguser)) -and !([string]::IsNullOrEmpty($PgSecPass)))
            {
                $Credential=CreateCredential -User $PgUser -Password $PgSecPass -NotConvertPassword -ErrorAction Stop
                New-PgCredential -Credential $Credential
            }
            else
            {
                Write-Verbose "Variable PostgresCmdletsCredential is null or empty"
            }
            
        }
        
}
function Remove-PgCredential{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param()
    $SavePath="HKCU:\Software\PsCred"
    if (Test-Path $SavePath)
    {
        Remove-Item -Path $SavePath -Force -ErrorAction Stop -Recurse
        
    }
    Set-Variable -Name PostgresCmdletsCredential -Force -Scope Global -Value $null -Visibility Private

    
}
function Start-Vacuum{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        [string]$Name,
        [switch]$Full,
        [switch]$Analyze,
        [switch]$OnlyAnalyze,
        [int]$Jobs
    )
    begin
    {
        if ($PSCmdlet.MyInvocation.BoundParameters['Credential'])
        {
            New-PgCredential -Credential $Credential -ErrorAction Stop  | Out-Null 
            $PgCredentialInfo=Get-PgCredential 
        }
        else
        {
            $PgCredentialInfo=Get-PgCredential
            if ($PgCredentialInfo -eq $null)
            {
                New-PgCredential -ErrorAction Stop | Out-Null   
            }
        
        }
        $PgCredentialInfo=Get-PgCredential
        $Credential=$PgCredentialInfo.Credential
        [string]$PgUser=$Credential.UserName
        [string]$PgPassword=GetPlainTextPassword -SecString $Credential.Password
        if ([string]::IsNullOrEmpty($PgUser) -or [string]::IsNullOrEmpty($PgPassword))
        {
            Write-Error "Credential is null or empty" -ErrorAction Stop
        }
        $PgPathInfo=$PgCredentialInfo.PgPathInfo
        $VacuumdbPath=$PgPathInfo["vacuumdb.exe"]
        if ([string]::IsNullOrEmpty($VacuumdbPath))
        {
            Write-Error "vacuumdb.exe not found" -ErrorAction Stop
        }
        if ($PSBoundParameters["Jobs"])
        {
            $LogicalProcessorsCount=GetLogicalProcessorsCount
            if (!($Jobs -gt 0 -and $Jobs -le $LogicalProcessorsCount))
            {
                Write-Verbose "The value of the -Jobs parameter must be in the range [1 - $LogicalProcessorsCount]. Set -Jobs $LogicalProcessorsCount" -Verbose
                $Jobs=$LogicalProcessorsCount
            }
        }
        else
        {
            $Jobs=1
        }
    
    }
    process
    {
        try
        {
            if ($Name -ne $null)
            {
                if ($name.length -gt 63)
                {
                    Write-Error "The name is longer than 63 characters" -ErrorAction Stop
                }
                $VacuumDbArgs=@(
                    "-U $PgUser",
                    "--no-password",
                    "--dbname $Name"
                )
                if (!($PSBoundParameters["Full"].Ispresent))
                {
                    $VacuumDbArgs+="--jobs=$Jobs"      
                }
                  
                if (!($PSBoundParameters["OnlyAnalyze"].isPresent))
                {
                    if ($PSBoundParameters["Full"].IsPresent)
                    {
                        $VacuumDbArgs+="--full"
                    }
                    if ($PSBoundParameters["Analyze"].IsPresent)
                    {
                        $VacuumDbArgs+="--analyze"
                    }
                }
                else
                {
                    $VacuumDbArgs+="--analyze-only"
                }
                
                $VerboseOutput=$False
                if ($PSBoundParameters["Verbose"].IsPresent)
                {
                    $VacuumDbArgs+="--verbose"
                    if($PSBoundParameters["Verbose"].IsPresent)
                    {
                        $VerboseOutput=$true    
                    }
                
                }
                $BeginFunction=get-date
                Write-Verbose "$VacuumdbPath $VacuumDbArgs" -Verbose
                Write-Verbose "$Name :Vacuum is working.. Please wait.." -Verbose
                $Result=InvokeExe -ExeFile $VacuumdbPath -Args $VacuumDbArgs -EnvVar $(@{"PGPASSWORD"=$PgPassword}) -VerboseOutput:$VerboseOutput
                if ($Result.exitcode -eq 0)
                {
                    $RunningTime=New-TimeSpan -Start $BeginFunction
                    $OutRes=New-Object -TypeName psobject
                    $OutRes | Add-Member -MemberType NoteProperty -Name Name -Value $Name
                    $OutRes | Add-Member -MemberType NoteProperty -Name VacuumTime -Value $RunningTime                     
                    $OutRes
                }
                else
                {
                    Write-Error "ExitCode: $($Result.exitcode) StdErr: $($Result.stdErr) StdOut: $($Result.StdOut)" -ErrorAction Stop
                }
                    
               
            }
            
        }
        catch
        {
            Write-Error $_
        }
    }
    end
    {
        
    }
}
function Get-PgServerInfo{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param(
        $Credential
    )
        if ($PSCmdlet.MyInvocation.BoundParameters['Credential'])
        {
            New-PgCredential -Credential $Credential -ErrorAction Stop  | Out-Null 
            $PgCredentialInfo=Get-PgCredential 
        }
        else
        {
            $PgCredentialInfo=Get-PgCredential
            if ($PgCredentialInfo -eq $null)
            {
                New-PgCredential -ErrorAction Stop | Out-Null   
            }
        
        }
        $PgVersion=Invoke-PgQuery -Query "SELECT version();"
        $PgSettings=Invoke-PgQuery -Query "SELECT name, setting FROM pg_settings"
        
        [string]$DataPath=($PgSettings | where-object {$_.name -eq "data_directory"}).setting -replace "/","\"
        [string]$ConfigPath=($PgSettings | where-object {$_.name -eq "config_file"}).setting -replace "/","\"
        
        if ($Pgversion.Version -match ".+\s(\d{1,2}\.\d{1,4})")
        {
            [version]$PgVer=$Matches[1]
        }
        else
        {
            Write-Error "Error parse $($Pgversion.Version)"
        }
        $PgServicesInfo=GetServiceInfo -MatchBinPath "\\pg_ctl.exe"
        $PgServiceInfo=$PgServicesInfo | Where-Object {$_.CommandLine -match [regex]::Escape($DataPath)}
        $ServiceName=$PgServiceInfo.DisplayName
        $RunningAs=$PgServiceInfo.RunningAs
        $Status=$PgServicesInfo.Status
        $BinaryPath=Split-Path $PgServicesInfo.ImagePath 
        $PgInfo=New-Object PsObject
        $PgInfo | Add-Member -MemberType NoteProperty -Name Description -Value $PgVersion.Version
        $PgInfo | Add-Member -MemberType NoteProperty -Name ServiceName -Value $ServiceName
        $PgInfo | Add-Member -MemberType NoteProperty -Name Version -Value $PgVer
        $PgInfo | Add-Member -MemberType NoteProperty -Name DataPath -Value $DataPath
        $PgInfo | Add-Member -MemberType NoteProperty -Name ConfigPath -Value $ConfigPath
        $PgInfo | Add-Member -MemberType NoteProperty -Name BinaryPath -Value $BinaryPath
        $PgInfo | Add-Member -MemberType NoteProperty -Name RunningAs -Value $RunningAs
        $PgInfo | Add-Member -MemberType NoteProperty -Name ServiceStatus -Value $Status
        $PgInfo
}
Function GetPgbinPath{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param()
    $TestAdmin = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $IsAdmin=$TestAdmin.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if ($IsAdmin)
    {
        [array]$PgProcess=Get-WmiObject -Query "Select * from win32_process where name = 'postgres.exe'" | Where-Object {$_.ExecutablePath}
        if ($PgProcess -eq $null)
        {
            Write-Error "Running postgres process not found" -ErrorAction Stop
        }
        $PgPath=$PgProcess[0].ExecutablePath
    }
    else
    {
        $PgServiceInfo=GetServiceInfo -MatchBinPath "\\pg_ctl.exe"
        if ($PgServiceInfo.count -gt 1)
        {
            Write-Error "Multiple services postgres found. Try run powershel as administrator" -ErrorAction Stop
        }
        $PgPath=$PgServiceInfo.ImagePath
        if ([string]::IsNullOrEmpty($PgPath))
        {
            Write-Error "pg_ctl.exe path not found. Try run powershel as administrator" -ErrorAction Stop
        }
    }

    $PgBinPath=Split-Path -Path $PgPath
    Write-Verbose "Postgres path $PgBinPath"
    $PgBinPath
}
function GetPgAppPaths{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    param(
        [parameter(Mandatory=$true)]
        [string[]]$AppNames
        #[string]$PgBinPath
    )

    $PgBinPath=GetPgbinPath    
    
    
    if (!(Test-Path $PgBinPath))
    {
        Write-Error "$PgBinPath not found" -ErrorAction Stop
    }
    $AppPathList=@{}
    $AppNames | foreach {
        $AppName=$_
        [string]$AppPath=Join-Path -Path $PgBinPath -ChildPath $AppName
        if(!(Test-Path $AppPath))
        {
            Write-Error "$AppName not found in $PgBinPath"
        }
        else
        {
            $AppPathList.Add($AppName,$AppPath)
        }
       
    }
    $AppPathList
}
function GetServiceInfo{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param([string]$MatchBinPath)
    $stdregProv = Get-Wmiobject -list "StdRegProv" -namespace root\default
    function RegGetValue
    {
        [CmdletBinding()]
        param(
        [parameter(Mandatory=$true)]
        [string]$Key,
        [parameter(Mandatory=$true)]
        [string]$Value,
        [parameter(Mandatory=$true)]
        [ValidateSet("GetStringValue","GetBinaryValue","GetDWORDValue","GetQWORDValue","GetMultiStringValue")]
        [string]$GetValue
        )
        if ($stdregprov -eq $null)
        {
            Write-Error "Variable StdRegProv Null"
        }
        $ResultProp=@{
        "GetStringValue"="Svalue"
        "GetBinaryValue"="Uvalue"
        "GetDWORDValue"="UValue"
        "GetQWORDValue"="UValue"
        "GetMultiStringValue"="Svalue"
        }
        $ErrorCode=@{
        "1"="Value doesn't exist"
        "2"="Key doesn't exist"
        "2147749893"="Wrong value type"
        "5"="Access Denied"
        "6"="Wrong Key String"
        }
        $hk=@{

        "HKEY_CLASSES_ROOT"=2147483648
        "HKEY_CURRENT_USER"=2147483649
        "HKEY_LOCAL_MACHINE"=2147483650
        "HKEY_USERS"=2147483651
        "HKEY_CURRENT_CONFIG"=2147483653

        }
        if($Key -match "(.+?)\\(.+)")
        {
            if ($hk.Keys -eq $matches[1])
            {
                $RootHive=$hk[$matches[1]]
                $KeyString=$matches[2]
                $StdRegProvResult=$StdRegProv | Invoke-WmiMethod -Name $GetValue -ArgumentList $RootHive,$KeyString,$Value
            }
            else
            {
                Write-Error "$($matches[1]) Does not belong to the set $($hk.Keys)" -ErrorAction Stop
            }
            if ($StdRegProvResult.returnvalue -ne 0)
            {
                if ($ErrorCode["$($StdRegProvResult.returnvalue)"] -ne $null)
                {
                    $er=$ErrorCode["$($StdRegProvResult.returnvalue)"]
                    Write-Error "$Er! Key $Key Value $Value "
                }
                else
                {
                    $er=$StdRegProvResult.returnvalue
                    Write-Error "$GetValue return $Er! Key $Key Value $Value "
                }
        
            }
            else
            {
                $StdRegProvResult.($ResultProp["$GetValue"])
            }
        }
        else
        {
            Write-Error "$Key not valid"
        }

    }
    function RegEnumKey
    {
        [CmdletBinding()]
        param(
        [parameter(Mandatory=$true)]
        [string]$Key
        )
        $ErrorActionPreference="Stop"
        if ($stdregprov -eq $null)
        {
            Write-Error "Variable StdRegProv Null"
        }
        $ErrorCode=@{
        "1"="Value doesn't exist"
        "2"="Key doesn't exist"
        "5"="Access Denied"
        "6"="Wrong Key String"
        }
        $hk=@{

        "HKEY_CLASSES_ROOT"=2147483648
        "HKEY_CURRENT_USER"=2147483649
        "HKEY_LOCAL_MACHINE"=2147483650
        "HKEY_USERS"=2147483651
        "HKEY_CURRENT_CONFIG"=2147483653
        }
        if($Key -match "(.+?)\\(.+)")
        {
        $StdRegProvResult=$StdRegProv.EnumKey($hk[$matches[1]],$matches[2])
            if ($StdRegProvResult.returnvalue -ne 0)
            {
                if ($ErrorCode["$($StdRegProvResult.returnvalue)"] -ne $null)
                {
                    $er=$ErrorCode["$($StdRegProvResult.returnvalue)"]
                }
                else
                {
                    $er=$StdRegProvResult.returnvalue
                }
            Write-Error "$Er key $Key"
        
            }
            else
            {
                $StdRegProvResult.snames
            }
        }
        else
        {
            Write-Error "$Key not valid"
        }

    }

    function RegEnumValues
    {
        [CmdletBinding()]
        param(
        [parameter(Mandatory=$true)]
        [string]$Key
        )
        $ErrorActionPreference="Stop"
        if ($stdregprov -eq $null)
        {
            Write-Error "Variable StdRegProv Null"
        }
        $ErrorCode=@{
        "1"="Value doesn't exist"
        "2"="Key doesn't exist"
        "5"="Access Denied"
        "6"="Wrong Key String"
        }
        $hk=@{

        "HKEY_CLASSES_ROOT"=2147483648
        "HKEY_CURRENT_USER"=2147483649
        "HKEY_LOCAL_MACHINE"=2147483650
        "HKEY_USERS"=2147483651
        "HKEY_CURRENT_CONFIG"=2147483653
        }
        if($Key -match "(.+?)\\(.+)")
        {
        $StdRegProvResult=$StdRegProv.EnumValues($hk[$matches[1]],$matches[2])
            if ($StdRegProvResult.returnvalue -ne 0)
            {
                if ($ErrorCode["$($StdRegProvResult.returnvalue)"] -ne $null)
                {
                    $er=$ErrorCode["$($StdRegProvResult.returnvalue)"]
                }
                else
                {
                    $er=$StdRegProvResult.returnvalue
                }
            Write-Error "$Er key $Key"
        
            }
            else
            {
                $StdRegProvResult.snames
            }
        }
        else
        {
            Write-Error "$Key not valid"
        }

    }
    function GetServiceInfoFromRegistry
    {
        [cmdletbinding()]
        param([string]$MatchBinPath)
        try
        {
            function GetServiceFromRegistry
            {
                    param([string]$RootKey,[array]$SubKeys,[string]$MatchBinPath)
                    function CreateServiceInfo
                    {
                        param([string]$ServiceName)
                        $CommandLine =RegGetValue -key $ChildPath -Value "ImagePath" -GetValue GetStringValue -ErrorAction SilentlyContinue -Verbose:$false
                        $DisplayName=RegGetValue -key $ChildPath -Value "DisplayName" -GetValue GetStringValue -ErrorAction SilentlyContinue -Verbose:$false
                        $ObjectName=RegGetValue -key $ChildPath -Value "ObjectName" -GetValue GetStringValue -ErrorAction SilentlyContinue -Verbose:$false
                        if ($CommandLine -match "(.+\.exe)")
                        {
                            $ImagePath=$Matches[1]
                            $ImagePath=$ImagePath -replace '"'
                        }
                        else
                        {
                            $ImagePath=$CommandLine
                        }
                        $TmpObject= New-Object psobject
                        $TmpObject | Add-Member -MemberType NoteProperty -Name DisplayName -Value $DisplayName
                        $TmpObject | Add-Member -MemberType NoteProperty -Name Name -Value $ServiceName
                        $TmpObject | Add-Member -MemberType NoteProperty -Name ImagePath -Value $ImagePath
                        $TmpObject | Add-Member -MemberType NoteProperty -Name CommandLine -Value  $CommandLine
                        $TmpObject | Add-Member -MemberType NoteProperty -Name RunningAs -Value  $ObjectName
                        $TmpObject  
                    }
                    $SubKeys | foreach {
                        $ChildPath=Join-Path -Path $RootKey -ChildPath $_      
                        $ServiceName=$_
                        $ImagePath=$null
                        $ImagePath =RegGetValue -key $ChildPath -Value "ImagePath" -GetValue GetStringValue -ErrorAction SilentlyContinue -Verbose:$false
                        if ($ImagePath -ne $null)
                        {
                            if ($PSBoundParameters["MatchBinPath"] -ne $null)
                            {
                                if ($ImagePath -match $MatchBinPath)
                                {
                                    CreateServiceInfo -ServiceName $ServiceName
                                }
                                else
                                {
                                    #Write-Verbose "Skip $ImagePath"
                                }      
                            }
                            else
                            {
                                CreateServiceInfo  
                            }
                        }
                        else
                        {
                            #Write-Verbose "$Computername $ChildPath Value ImagePath is Null"
                        }
                    }
            }
    
            $AllServices=@()
            $ServiceRootKey="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
            [array]$SubKeys=RegEnumKey -key $ServiceRootKey
            if ($PSBoundParameters["MatchBinPath"] -ne $null)
            {
                $AllServices+=GetServiceFromRegistry -RootKey $ServiceRootKey -SubKeys $SubKeys  -MatchBinPath $MatchBinPath
            }
            else
            {
                $AllServices+=GetServiceFromRegistry -RootKey $ServiceRootKey -SubKeys $SubKeys
            }
            if ($AllServices.count -ne 0)
            {
                $AllServices
            }
            else
            {
                Write-Error "not found $MatchBinPath"
            }
        }
        catch
        {
            Write-Error $_
        }
    
    }
    [array]$ServicesInfoRg=GetServiceInfoFromRegistry -MatchBinPath $MatchBinPath -ErrorAction Stop
    $ServicesInfoRg | foreach {
        $ServiceInfoRg=$_
        $ServiceInfo=Get-Service -Name $($ServiceInfoRg.name) -ErrorAction Stop
        if ($serviceinfo -eq $null)
        {
            Write-Error "Get-Service return null" -ErrorAction Stop
        }
        
        $ServiceInfoRg | Add-Member -MemberType NoteProperty -Name Status -Value $($ServiceInfo.Status) -ErrorAction Stop
        $ServiceInfoRg | Add-Member -MemberType NoteProperty -Name StartType -Value $($ServiceInfo.StartType) -ErrorAction Stop
        $ServiceInfoRg
    }
}
function InvokeExe{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
        param(
            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [String]$ExeFile,
            [Parameter(Mandatory=$false)]
            [String[]]$Args,
            [hashtable]$EnvVar,
            [switch]$VerboseOutput,
            [string]$LogPath,
            [Parameter(Mandatory=$false)]
            [String]$Verb,
            [int]$Encoding
        )    
        if (!([string]::IsNullOrEmpty($PSBoundParameters["LogPath"])))
        {
            New-Item -ItemType File -Path $LogPath -ErrorAction Stop -Force | Out-Null
        }
        $oPsi = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        [string[]]$MUILanguages=(Get-WmiObject -query "select MUILanguages from win32_operatingsystem" ).MUILanguages
        if ($PSBoundParameters['Encoding'] -ne $null)
        {
            $ProcessEncoding=[System.Text.Encoding]::GetEncoding($Encoding)
        }
        elseif($MUILanguages -eq "ru-RU")
        {
            $ProcessEncoding=[System.Text.Encoding]::GetEncoding(1251)
        }
        $oPsi.StandardOutputEncoding=$ProcessEncoding
        $oPsi.StandardErrorEncoding=$ProcessEncoding
        $oPsi.CreateNoWindow = $true
        $oPsi.UseShellExecute = $false
        $oPsi.RedirectStandardOutput = $true
        $oPsi.RedirectStandardError = $true
        if ($PSBoundParameters["EnvVar"] -ne $null)
        {
            $EnvVar.Keys | foreach {
                [string]$Key=$_
                [string]$Value=$EnvVar[$Key]
                $oPsi.EnvironmentVariables.Add($Key,$Value)
            }
        }
        $oPsi.FileName = $ExeFile
    
        if (! [String]::IsNullOrEmpty($Args)) 
        {
            $oPsi.Arguments = $Args
        }
        if (! [String]::IsNullOrEmpty($Verb)) 
        {
            $oPsi.Verb = $Verb
        }
    
        $oProcess = New-Object -TypeName System.Diagnostics.Process
        $oProcess.StartInfo = $oPsi

        $oStdOutBuilder = New-Object -TypeName System.Text.StringBuilder
        $oStdErrBuilder = New-Object -TypeName System.Text.StringBuilder
        $StdOutObject=New-Object -TypeName psobject
        $StdErrObject=New-Object -TypeName psobject
        $StdOutObject | Add-Member -MemberType NoteProperty -Name StrBuilder -Value $oStdOutBuilder
        $StdOutObject | Add-Member -MemberType NoteProperty -Name LogPath -Value $LogPath
        $StdOutObject | Add-Member -MemberType NoteProperty -Name VerboseOutput -Value $($PSBoundParameters["VerboseOutput"].IsPresent)
        $StdErrObject | Add-Member -MemberType NoteProperty -Name StrBuilder -Value $oStdErrBuilder
        $StdErrObject | Add-Member -MemberType NoteProperty -Name LogPath -Value $LogPath
        $StdErrObject | Add-Member -MemberType NoteProperty -Name VerboseOutput -Value $($PSBoundParameters["VerboseOutput"].IsPresent)

        $sScripBlock = {
            if (!([String]::IsNullOrEmpty($EventArgs.Data))) 
            {
                
                if (!($Event.MessageData.VerboseOutput -eq $true) -and [string]::IsNullOrEmpty($event.MessageData.LogPath))
                {
                    $Event.MessageData.StrBuilder.AppendLine($EventArgs.Data)    
                }
                else
                {
                    if (!([string]::IsNullOrEmpty($event.MessageData.LogPath)))
                    {
                        $($EventArgs.Data) | Out-File -FilePath $($event.MessageData.LogPath) -Append -Force -WhatIf:$false -Confirm:$false  -ErrorAction Stop 
                    }
                    if ($Event.MessageData.VerboseOutput -eq $true)
                    {
                        Write-Verbose "$($EventArgs.Data)" -Verbose     
                    }    
                }
                
                
                
                    
  
            }
        }
        $oStdOutEvent = Register-ObjectEvent -InputObject $oProcess -Action $sScripBlock -EventName 'OutputDataReceived' -MessageData $StdOutObject
        $oStdErrEvent = Register-ObjectEvent -InputObject $oProcess -Action $sScripBlock -EventName 'ErrorDataReceived' -MessageData $StdErrObject
        Unregister-Event -SourceIdentifier ProcessExitedEvent -Confirm:$false -WhatIf:$false -ErrorAction SilentlyContinue
        Remove-Event -SourceIdentifier ProcessExitedEvent -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false
        Register-ObjectEvent -InputObject $oProcess -EventName 'Exited' -SourceIdentifier ProcessExitedEvent
        
        [Void]$oProcess.Start()
         
        $oProcess.BeginOutputReadLine()
        $oProcess.BeginErrorReadLine()
        $ProcessClose=$false
        try
        {
                if ($PSBoundParameters["VerboseOutput"].isPresent -or !([string]::IsNullOrEmpty($PSBoundParameters["LogPath"])))
                {  
                    do 
                    {
                        Start-Sleep -Milliseconds 5
                    }while(!($oProcess.HasExited))    
                    $ProcessClose=$true
                }
                else
                {
         
                        Wait-Event -SourceIdentifier ProcessExitedEvent -ErrorAction Stop | Out-Null
                        $ProcessClose=$true
                
                }
        }
        finally
        {
                if (!($ProcessClose))
                {
                    Write-Verbose "Try stop process $($oProcess.ID) $($oProcess.name)" -Verbose
                    Stop-Process -Id $($oProcess.ID) -WhatIf:$false -Confirm:$false -Force    
                }
                
                Unregister-Event -SourceIdentifier $oStdOutEvent.Name -Confirm:$false -WhatIf:$false
                Unregister-Event -SourceIdentifier $oStdErrEvent.Name -Confirm:$false -WhatIf:$false
                Unregister-Event -SourceIdentifier ProcessExitedEvent -Confirm:$false -WhatIf:$false
                Remove-Event -SourceIdentifier ProcessExitedEvent -Confirm:$false -WhatIf:$false -ErrorAction SilentlyContinue
        }

    
        
        
        $oResult = New-Object -TypeName PSObject -Property (@{
            "ExeFile"  = $ExeFile;
            "Args"     = $Args -join " ";
            "ExitCode" = $oProcess.ExitCode;
            "StdOut"   = $StdOutObject.StrBuilder.ToString().Trim();
            "StdErr"   = $StdErrObject.StrBuilder.ToString().Trim();
        })

        return $oResult
}
function Compress7zip{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [string[]]$Path,
        [string]$DestinationPath,
        [string]$ArchiveName,
        [string]$Password,
        [switch]$NoCompression,
        [validateset("7z","zip")]
        [string]$Type,
        [switch]$DelAfterCompress
    )
    if ($PSBoundParameters["Type"] -eq $null)
    {
        $Type="zip"
    }
function Get7zipPath
{
    [cmdletbinding()]
    param(
        [string]$7ZipPath="$env:ProgramFiles\7-zip"
    )
    $7zip=Join-Path -Path $7ZipPath -ChildPath "7z.exe"
    Write-Verbose "check $7zip"
    if (Test-Path -Path $7zip)
    {
        $7zip
    }
    elseif(${env:ProgramFiles(x86)})
    {
        $7ZipPath="${env:ProgramFiles(x86)}\7-zip"
        $7zip=Join-Path -Path $7ZipPath -ChildPath "7z.exe"
        Write-Verbose "check $7zip"
        if (Test-Path -Path $7zip)
        {
            $7zip
        }
        else
        {
            Write-Error "7zip not found" 
        }
    }
    else
    {
        Write-Error "7zip not found"
    }
}
    
        if ([string]::IsNullOrEmpty($PSBoundParameters["ArchiveName"]))
        {
            $ArchiveName=Split-Path -Path $Path[0] -Leaf
            if($ArchiveName -match "^.+(\..+?)$")
            {
                $ArchiveName=$ArchiveName -replace "$($Matches[1])$"
            }    
        }
        
        if([string]::IsNullOrEmpty($PSBoundParameters['DestinationPath']))
        {
            $RootFolder=Split-Path -Path $path[0] -Parent
            $DestinationPath=Join-Path $RootFolder -ChildPath $ArchiveName
        }
    #Write-Debug -Debug dbg
    #https://axelstudios.github.io/7z/#!/
    $7Zip=Get7zipPath -ErrorAction Stop
    $EscapePath=@()
    $Path | foreach {
        $EscapePath+=$('"'+$_+'"')
    }
    $7ZipArgs=@(
        "a",
        "-ssw",
        "-t$Type",
        $('"'+$DestinationPath+'"'),
        $EscapePath
    )

    if ($PSBoundParameters['password'])
    {
        $7ZipArgs+="-p$Password"
    }
    if ($PSBoundParameters["DelAfterCompress"].isPresent)
    {
        $7ZipArgs+="-sdel"
    }
    if ($PSBoundParameters["NoCompression"].isPresent)
    {
        #$7ZipArgs+="-m0=Copy"
        $7ZipArgs+="-mx0"
    }
    $ProcessorCount=GetLogicalProcessorsCount
    $7ZipArgs+="-mmt$ProcessorCount"
    Write-Verbose "InvokeExe $7Zip -Args $7ZipArgs"
    $Res=InvokeExe -ExeFile $7Zip -Args $7ZipArgs -Encoding 866
    if ($Res.ExitCode -eq 0)
    {
        Write-Verbose "$($Res.stdout)"
        $DestinationPath=$DestinationPath+"."+$Type
        Test-Path $DestinationPath -ErrorAction Stop | Out-Null
        $DestinationPath
        <#$StdOut=$Res.StdOut -split "`n"
        $DstPath=$StdOut | Select-String -SimpleMatch "Path"
        if ($DstPath -match "Path = (.+)")
        {
            $Matches[1]
        }
        else
        {
            Write-Error "$($Res.StdOut)" -ErrorAction Stop
        }#>     
    }
    else
    {
        Write-Error "$($Res.StdOut)" -ErrorAction Stop
    }
    
}
function CreateCredential{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$User,
        [string]$Password,
        [switch]$NotConvertPassword
    )
    
    Write-Verbose "Create Credential User $User, Password $password"
    
    if ($PSBoundParameters["Password"])
    {
        if (!($PSBoundParameters["NotConvertPassword"].isPresent))
        {
            $SecPassword = ConvertTo-SecureString -String $Password -AsPlainText -Force    
        }
        else
        {
            $SecPassword=ConvertTo-SecureString -String $Password -Force
        }
        
        $Credential = New-Object System.Management.Automation.PSCredential($User,$SecPassword)  
    }
    else
    {
        $Credential = New-Object System.Management.Automation.PSCredential($User,(new-object System.Security.SecureString))
    }
    
    
    $Credential
}
function GetLogicalProcessorsCount{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    $LogicalProcessorCount=0
    Get-WmiObject -Query "Select NumberOfLogicalProcessors From Win32_Processor" | foreach {
        if ($_.NumberOfLogicalProcessors -ge 1)
        {
            $LogicalProcessorCount+=$_.NumberOfLogicalProcessors   
        }
    
    }
    $LogicalProcessorCount    
}
function GetPlainTextPassword ($SecString){
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    $BSTR =[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecString)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $PlainPassword
}
function Decompress-Archive{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [string]$Path,
        [string]$DestinationPath=$env:TEMP,
        [string]$Password,
        [switch]$DelAfterDecompress,
        [string]$AppPath
    )
    function Get7zippath
    {
        [cmdletbinding()]
        param(
            [string]$zippath="$env:ProgramFiles\7-zip",
            [string]$Base64String #Encoding sfx archive(use 7z to create sfx)
        )

            $7zip=Join-Path -Path $zippath -ChildPath "7z.exe"
       
            if (Test-Path -Path $7zip)
            {
                 Write-Verbose "check $7zip"
                $7zip=Get-Item -Path $7zip -ErrorAction Stop
                $7zip
            }
            elseif(Test-Path "${env:ProgramFiles(x86)}\7-zip\7z.exe")
            {
                $zippath="${env:ProgramFiles(x86)}\7-zip"
                $7zip=Join-Path -Path $zippath -ChildPath "7z.exe"
                Write-Verbose "check $7zip"
                if (Test-Path -Path $7zip)
                {
                    $7zip=Get-Item -Path $7zip -ErrorAction Stop
                    $7zip
                }

            }
            else
            {
                Write-Verbose "Installed 7z not found"
                if ($PSBoundParameters['Base64String'])
                {
                    Write-Verbose "try use Base64String"
                    $7zipSfx=ConvertStringToBinary -Base64String $Base64String -FilePath "$env:TEMP\7zsfx.exe"
                    $7zPath="$env:TEMP\7z"
                    $Res=InvokeExe -ExeFile $7zipSfx.fullname -Args  $("-o"+'"'+$7zPath+'"'),"-y" -ErrorAction Stop
                    if ($Res.ExitCode -eq 0)
                    {
                        Write-Verbose "$($Res.stdout)"
                    }
                    else
                    {
                        Write-Error "$($Res.StdOut)" -ErrorAction Stop
                    }
                    $7zip=Join-Path $7zPath -ChildPath 7z.exe
                    $7zip=Get-Item -Path $7zip -ErrorAction Stop
                    $7zip
                }
                else
                {
                    Write-Error "7zip not found"
                
                }
            
            }

   
    }
    function Decompress7zip
    {
            [cmdletbinding()]
            param(
                [parameter(Mandatory=$true)]
                [string]$Path,
                [string]$DestinationPath=$env:TEMP,
                [string]$Password,
                [switch]$DelAfterDecompress,
                [string]$ZipAppPath
            )
        if ($PSBoundParameters['ZipAppPath'] -ne $null)
        {
        
            $7Zip=Get-Item $ZipAppPath -ErrorAction Stop
        }
        else
        {
            $7Zip=Get7zipPath -ErrorAction Stop   
        }
    
        $7ZipArgs=@(
            "x $Path",
            #"e $Path",
            "-o$DestinationPath",
            "-y"
        )
        if ($PSBoundParameters['password'])
        {
            $7ZipArgs+="-p$Password"
        }
        Write-Verbose "$7Zip $7ZipArgs"
        $Res=InvokeExe -ExeFile $7Zip.Fullname -Args $7ZipArgs
        if ($Res.ExitCode -eq 0)
        {
            Get-Item -Path $DestinationPath
            Write-Verbose "$($Res.stdout)"
            if ($PSBoundParameters["DelAfterDecompress"].isPresent)
            {
                Write-Verbose "Remove-Item -Path $Path -Force"
                Remove-Item -Path $Path -Force
            }
        }
        else
        {
            $Res
            Write-Error "$($Res.StdOut)" -ErrorAction Stop
        
        }
    
    }
    function GetWinRarPath
    {
        [cmdletbinding()]
        param(
            [string]$WinRarPath="$env:ProgramFiles\WinRar",
            [string]$Base64String #Encoding sfx archive(use WinRar to create sfx)
        )

            $WinRar=Join-Path -Path $WinRarPath -ChildPath "rar.exe"
       
            $AllWinrar=@()
            if (Test-Path -Path $WinRar)
            {
                 Write-Verbose "check $WinRar"
                $AllWinrar+=Get-Item -Path $WinRar -ErrorAction Stop
            }
            if(Test-Path "${env:ProgramFiles(x86)}\WinRar\rar.exe")
            {
                $zippath="${env:ProgramFiles(x86)}\WinRar"
                $WinRar=Join-Path -Path $zippath -ChildPath "rar.exe"
                Write-Verbose "check $WinRar"
                if (Test-Path -Path $WinRar)
                {
                    $AllWinrar+=Get-Item -Path $WinRar -ErrorAction Stop
                }

            }
            if ($AllWinrar.count -eq 0)
            {
                Write-Verbose "Installed WinRar not found"
                if ($PSBoundParameters['Base64String'])
                {
                    Write-Verbose "try use Base64String"
                    $WinRarSfx=ConvertStringToBinary -Base64String $Base64String -FilePath "$env:TEMP\WinRarsfx.exe"
                    $WinRarPath="$env:TEMP\WinRar"
                    $Res=InvokeExe -ExeFile $WinRarSfx.fullname -Args  $("-o"+'"'+$WinRarPath+'"'),"-y" -ErrorAction Stop
                    if ($Res.ExitCode -eq 0)
                    {
                        Write-Verbose "$($Res.stdout)"
                    }
                    else
                    {
                        Write-Error "$($Res.StdOut)" -ErrorAction Stop
                    }
                    $WinRar=Join-Path $WinRarPath -ChildPath rar.exe
                    $AllWinrar+=Get-Item -Path $WinRar -ErrorAction Stop
                
                }
                else
                {
                    Write-Error "WinRar not found"
                }
            
            }

            if ($AllWinrar.count -gt 1)
            {
                Write-Verbose -Message "Found $($AllWinrar.count) Select newest"
                $AllWinrar | foreach {$_.VersionInfo} | Sort-Object -Property fileversion -Descending | Select-Object -First 1 | foreach {Get-Item -Path $_.FileName} 
            }
            elseif($AllWinrar.count -ne 0)
            {
                $AllWinrar[0] 
            }
    
    }
    function DecompressWinRar
    {
            [cmdletbinding()]
            param(
                [parameter(Mandatory=$true)]
                [string]$Path,
                [string]$DestinationPath=$env:TEMP,
                [string]$Password,
                [switch]$DelAfterDecompress,
                [string]$WinRarAppPath
            )
        if ($PSBoundParameters['WinRarAppPath'] -ne $null)
        {
        
            $WinRar=Get-Item $WinRarAppPath -ErrorAction Stop
        }
        else
        {
            $WinRar= GetWinRarPath -ErrorAction Stop   
        }
    
        $WinRarArgs=@(
            $("x "+'"'+$Path+'"'),
            $('"'+$DestinationPath+'"'),
            "-y"
        )
        if ($PSBoundParameters['password'])
        {
            $WinRarArgs+="-p$Password"
        }
        Write-Verbose "$WinRar $WinRarArgs"
        $Res=InvokeExe -ExeFile $WinRar.Fullname -Args $WinRarArgs
        if ($Res.ExitCode -eq 0)
        {
            Get-Item -Path $DestinationPath
            Write-Verbose "$($Res.stdout)"
            if ($PSBoundParameters["DelAfterDecompress"].isPresent)
            {
                Write-Verbose "Remove-Item -Path $Path -Force"
                Remove-Item -Path $Path -Force
            }
        }
        else
        {
        
            Write-Error "ExitCode: $($Res.ExitCode) $($Res.StdErr) $($Res.StdOut)" -ErrorAction Stop
        
        }
    
    }
    function DecompressZIP
    {
        [cmdletbinding()]
        param(
                [parameter(Mandatory=$true)]
                [string]$Path,
                [string]$DestinationPath=$env:TEMP,
                [switch]$DelAfterDecompress,
                [switch]$ShowProgressBar
            )
    
        try
        {
            if (!($Path -match ".+\.zip$"))
            {
                Write-Error "Incorrect file, only zip supported" -ErrorAction Stop
            }
            $shell = New-Object -ComObject shell.application
            $zip = $shell.NameSpace($Path)
            $Files=$zip.items()
            Write-Verbose "Use shell.application Try extract"
            if (!(Test-Path $DestinationPath))
            {
                Write-Verbose "New-Item -ItemType Directory -Path $DestinationPath"
                New-Item -ItemType Directory -Path $DestinationPath -ErrorAction Stop | Out-Null
            }
            foreach ($file in $Files) 
            {
                if ($File -ne $null)
                {
                    if ($PSBoundParameters["ShowProgressBar"] -ne $null)
                    {
                    
                        $shell.Namespace($DestinationPath).CopyHere($file,16) 
                    }
                    else
                    {
                    
                        $shell.Namespace($DestinationPath).CopyHere($file,20) 
                   
                    }
                }
            
            
            }
            if ($PSBoundParameters["DelAfterDecompress"].isPresent)
            {
                Write-Verbose "Remove-Item -Path $Path -Force"
                Remove-Item -Path $Path -Force
            }
            Get-Item -Path $DestinationPath
        }
        catch
        {
            Write-Error $_ -ErrorAction Stop
        }
    
    }
    
    $ArhiveFile=Get-Item -Path $Path
    if ($ArhiveFile.PSIsContainer)
    {
        Write-Error "Incorrect file $Path" -ErrorAction Stop
    }
    $Arhivators=@()
    if ($PSBoundParameters['AppPath'] -ne $null)
    {
        
        $Arhivators+=Get-Item $AppPath -ErrorAction Stop
    }
    if ( $Arhivators.count -eq 0)
    {
        $Arhivators+=Get7zippath -ErrorAction SilentlyContinue
        $Arhivators+=GetWinRarPath -ErrorAction SilentlyContinue
    }
    $DecompressSucces=$false
    if ( $Arhivators.count -ne 0)
    {
        foreach ($Arhivator in $Arhivators)
        {
            try
            {
                if ($Arhivator.name -eq "7z.exe")
                {
                    Decompress7zip -Path $Path -DestinationPath $DestinationPath -ZipAppPath $Arhivator.fullname -ErrorAction Stop
                    $DecompressSucces=$true
                    break
                }
                if ($Arhivator.name -eq "rar.exe")
                {
                    DecompressWinRar -Path $Path -DestinationPath $DestinationPath -WinRarAppPath $Arhivator.fullname -ErrorAction Stop
                    $DecompressSucces=$true
                    break
                }
                

            }
            catch
            {
                Write-Verbose $_
            }
        }
       
    }
    
    if (!$DecompressSucces)
    {
        if ($Path -match ".+\.zip$" -and $PSBoundParameters['Password'] -eq $null)
        {
            Write-Verbose "Working Archive extractor not found, trying to use windows zip"
            DecompressZIP -Path $Path -DestinationPath $DestinationPath -ErrorAction Stop
        }
        else
        {
            Write-Error "$Path file extraction error" -ErrorAction Stop
        }
       
    }
    

}
function GetScriptPath{
    <#
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/PostgresCmdlets
        Requires: Powershell 2.0
    #>
    [cmdletbinding()]
    param()
    # If using PowerShell ISE
    if ($psISE)
    {
        $ScriptPath=$ScriptPath =  $psISE.CurrentFile.FullPath
    }
    # If using PowerShell 2.0 or lower
    else
    {
        $ScriptPath=$Global:MyInvocation.InvocationName
    }
    if ([string]::IsNullOrEmpty($ScriptPath))
    {
        Write-Error "GetScriptPath return null"
    }
    else
    {
        $ScriptPath
    }
}
