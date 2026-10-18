import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Existing SDK metadata parser only; no RepoManager load, install or acceptance methods. */
public final class LicenseProbe {
  static final Map<String,Object> report = new LinkedHashMap<>();
  static String hex(byte[] bytes) { StringBuilder b=new StringBuilder(); for(byte v:bytes)b.append(String.format("%02x",v&255));return b.toString(); }
  static String digest(String text,String kind)throws Exception {return hex(MessageDigest.getInstance(kind).digest(text.getBytes(StandardCharsets.UTF_8)));}
  static Object invoke(Object obj,String name)throws Exception {return obj.getClass().getMethod(name).invoke(obj);}
  static String json(Object value) {
    if(value==null)return "null";
    if(value instanceof Boolean || value instanceof Number)return value.toString();
    if(value instanceof Map){StringJoiner j=new StringJoiner(",","{","}");for(Object entry:((Map<?,?>)value).entrySet()){Map.Entry<?,?> e=(Map.Entry<?,?>)entry;j.add(json(e.getKey().toString())+":"+json(e.getValue()));}return j.toString();}
    if(value instanceof Collection){StringJoiner j=new StringJoiner(",","[","]");for(Object x:(Collection<?>)value)j.add(json(x));return j.toString();}
    StringBuilder q=new StringBuilder("\"");for(char c:value.toString().toCharArray()){if(c=='"'||c=='\\')q.append('\\').append(c);else if(c<32)q.append(String.format("\\u%04x",(int)c));else q.append(c);}return q.append('"').toString();
  }
  static Object progress(Class<?> cls,Map<String,Integer> counters) {
    return Proxy.newProxyInstance(cls.getClassLoader(),new Class<?>[]{cls},(proxy,m,args)->{
      String n=m.getName();
      if(n.equals("logError")||n.equals("logWarning"))counters.merge(n,1,Integer::sum);
      if(n.equals("toString"))return "ReadOnlyMetadataProgress";
      if(n.equals("hashCode"))return System.identityHashCode(proxy);
      if(n.equals("equals"))return proxy==args[0];
      Class<?> r=m.getReturnType();if(r==boolean.class)return false;if(r==double.class)return 0d;if(r==float.class)return 0f;if(r==int.class)return 0;if(r==long.class)return 0L;if(r.isAssignableFrom(cls))return proxy;return null;
    });
  }
  public static void main(String[] args) {
    report.put("schema","existing-sdk-official-license-parser-v1");report.put("softwareInstalled",false);report.put("licenseAcceptanceInvoked",false);report.put("emulatorLaunched",false);
    try {
      report.put("phase","VALIDATE_INPUT");
      if(args.length!=3)throw new IllegalArgumentException();
      Path sdk=Paths.get(args[0]).toRealPath(),general=Paths.get(args[1]).toRealPath(),play=Paths.get(args[2]).toRealPath();
      report.put("phase","LOAD_EXISTING_SDK_CLASSES");
      Class<?> handler=Class.forName("com.android.sdklib.repository.AndroidSdkHandler"),util=Class.forName("com.android.repository.impl.meta.SchemaModuleUtil"),pi=Class.forName("com.android.repository.api.ProgressIndicator");
      report.put("phase","READ_SCHEMA_MODULES");
      Object modules=handler.getMethod("getAllModules").invoke(null);Method four=null,five=null,unmarshal=null;
      report.put("handlerClass",handler.getName());report.put("schemaUtilClass",util.getName());report.put("progressInterface",pi.getName());
      for(Method m:util.getMethods())if(m.getName().equals("unmarshal")&&Modifier.isStatic(m.getModifiers())&&(m.getParameterCount()==4||m.getParameterCount()==5)&&InputStream.class.isAssignableFrom(m.getParameterTypes()[0])&&Collection.class.isAssignableFrom(m.getParameterTypes()[1])&&m.getParameterTypes()[2]==boolean.class&&m.getParameterTypes()[3]==pi&&(m.getParameterCount()==4||m.getParameterTypes()[4]==String.class)){if(m.getParameterCount()==5){if(five!=null)throw new IllegalStateException();five=m;}else{if(four!=null)throw new IllegalStateException();four=m;}}
      unmarshal=five!=null?five:four;
      if(unmarshal==null)throw new NoSuchMethodException();
      report.put("selectedUnmarshalSignature",unmarshal.toGenericString());
      report.put("unmarshalParameterCount",unmarshal.getParameterCount());
      List<Object> rows=new ArrayList<>();
      for(Path metadata:List.of(general,play)) {
        report.put("phase",metadata.equals(general)?"PARSE_OFFICIAL_GENERAL_XML":"PARSE_OFFICIAL_PLAY_XML");
        Map<String,Integer> counters=new LinkedHashMap<>();Object indicator=progress(pi,counters),repository;
        try(InputStream input=new BufferedInputStream(Files.newInputStream(metadata))){repository=unmarshal.invoke(null,unmarshal.getParameterCount()==4?new Object[]{input,modules,true,indicator}:new Object[]{input,modules,true,indicator,"official-readonly-metadata"});}
        report.put("lastParserLogCounts",counters);
        if(repository==null||counters.getOrDefault("logError",0)>0||counters.getOrDefault("logWarning",0)>0)throw new IllegalStateException();
        report.put("phase","READ_REMOTE_PACKAGE_METADATA");
        report.put("lastRepositoryClass",repository.getClass().getName());
        Object packages=invoke(repository,"getRemotePackage");if(!(packages instanceof Collection))throw new IllegalStateException();
        String target=metadata.equals(general)?"emulator":"system-images;android-35;google_apis_playstore;x86_64";List<Object> matches=new ArrayList<>();
        for(Object pkg:(Collection<?>)packages)if(target.equals(invoke(pkg,"getPath")))matches.add(pkg);
        if(matches.isEmpty())throw new IllegalStateException();
        for(Object pkg:matches){report.put("phase","READ_TARGET_PACKAGE_CHANNEL_REVISION");Object channel=invoke(pkg,"getChannel"),version=invoke(pkg,"getVersion");if(channel==null||version==null)throw new IllegalStateException();String rawChannel=String.valueOf(invoke(channel,"getId"));String channelRef=rawChannel.matches("[0-3]")?"channel-"+rawChannel:rawChannel;if(!channelRef.matches("channel-[0-3]"))throw new IllegalStateException();Map<String,Object> revision=new LinkedHashMap<>();for(String part:List.of("Major","Minor","Micro","Preview")){Object number=invoke(version,"get"+part);if(!(number instanceof Integer)||((Integer)number)<0)throw new IllegalStateException();revision.put(part.toLowerCase(Locale.ROOT),number);}report.put("phase","READ_TARGET_PACKAGE_LICENSE");Object license=invoke(pkg,"getLicense");if(license==null)throw new IllegalStateException();String id=(String)invoke(license,"getId"),value=(String)invoke(license,"getValue"),hash=(String)invoke(license,"getLicenseHash");
          if(!id.matches("[a-zA-Z0-9_.-]{1,100}")||!hash.matches("[0-9a-f]{40}")||!hash.equals(digest(value,"SHA-1")))throw new IllegalStateException();
          Method byPath=null,byFile=null,accepted=null;for(Method m:license.getClass().getMethods())if(m.getName().equals("checkAccepted")&&m.getParameterCount()==1&&(m.getParameterTypes()[0]==Path.class||m.getParameterTypes()[0]==File.class)){if(m.getParameterTypes()[0]==Path.class){if(byPath!=null)throw new IllegalStateException();byPath=m;}else{if(byFile!=null)throw new IllegalStateException();byFile=m;}}
          accepted=byPath!=null?byPath:byFile;
          if(accepted==null)throw new NoSuchMethodException();report.put("phase","READ_EXISTING_LICENSE_ACCEPTANCE");Object result=accepted.invoke(license,accepted.getParameterTypes()[0]==Path.class?sdk:sdk.toFile());if(!(result instanceof Boolean))throw new IllegalStateException();
          Map<String,Object> row=new LinkedHashMap<>();row.put("package",target);row.put("channelRef",channelRef);row.put("rawSDKChannelID",rawChannel);row.put("revision",revision);row.put("SDKVersionString",version.toString());row.put("licenseRef",id);row.put("SDKGetLicenseHash",hash);row.put("SDKGetValueSHA256",digest(value,"SHA-256"));row.put("SDKGetValueUTF8Bytes",value.getBytes(StandardCharsets.UTF_8).length);row.put("SDKCheckAccepted",result);row.put("acceptedArgumentType",accepted.getParameterTypes()[0].getName());row.put("selectedCheckAcceptedSignature",accepted.toGenericString());row.put("licenseClass",license.getClass().getName());row.put("parserLogCounts",counters);rows.add(row);
        }
      }
      report.put("status","READ_ONLY_SDK_PARSE_COMPLETED");report.put("packages",rows);report.put("allParsedLicensesAlreadyAccepted",!rows.isEmpty()&&rows.stream().allMatch(r->Boolean.TRUE.equals(((Map<?,?>)r).get("SDKCheckAccepted"))));
      report.put("installationAuthorizedByThisResult",false);
      System.out.println(json(report));
    } catch(Throwable error) {
      Throwable cause=error instanceof InvocationTargetException&&error.getCause()!=null?error.getCause():error;
      report.put("status","REFUSED_SDK_PARSE_OR_SCHEMA_UNSUPPORTED");report.put("errorClass",cause.getClass().getName());report.put("installationAuthorizedByThisResult",false);System.out.println(json(report));System.exit(2);
    }
  }
}
