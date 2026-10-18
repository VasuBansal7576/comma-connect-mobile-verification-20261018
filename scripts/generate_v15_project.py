#!/usr/bin/env python3
"""Produces an unsigned, dependency-free XCTest UI project; no XcodeGen download."""
import json, pathlib
root=pathlib.Path(__file__).resolve().parents[1]
project=root/'CIProbeV15.xcodeproj';project.mkdir(exist_ok=True)
objects={}
def obj(number,**fields):
    key=f'{number:024X}';objects[key]=fields;return key
host_source=obj(1,isa='PBXFileReference',lastKnownFileType='sourcecode.swift',path='ios/Host.swift',sourceTree='<group>')
ui_source=obj(2,isa='PBXFileReference',lastKnownFileType='sourcecode.swift',path='ios/V15InstalledUITests.swift',sourceTree='<group>')
handshake_source=obj(22,isa='PBXFileReference',lastKnownFileType='sourcecode.swift',path='ios/V15CIHandshake.swift',sourceTree='<group>')
handshake_build=obj(23,isa='PBXBuildFile',fileRef=handshake_source)
host_product=obj(3,isa='PBXFileReference',explicitFileType='wrapper.application',path='CIHost.app',sourceTree='BUILT_PRODUCTS_DIR')
ui_product=obj(4,isa='PBXFileReference',explicitFileType='wrapper.cfbundle',path='CIProbeUITests.xctest',sourceTree='BUILT_PRODUCTS_DIR')
host_build=obj(5,isa='PBXBuildFile',fileRef=host_source)
ui_build=obj(6,isa='PBXBuildFile',fileRef=ui_source)
products=obj(7,isa='PBXGroup',children=[host_product,ui_product],name='Products',sourceTree='<group>')
main=obj(8,isa='PBXGroup',children=[host_source,ui_source,handshake_source,products],sourceTree='<group>')
host_phase=obj(9,isa='PBXSourcesBuildPhase',buildActionMask=2147483647,files=[host_build],runOnlyForDeploymentPostprocessing=0)
ui_phase=obj(10,isa='PBXSourcesBuildPhase',buildActionMask=2147483647,files=[ui_build,handshake_build],runOnlyForDeploymentPostprocessing=0)
settings={'SDKROOT':'iphoneos','IPHONEOS_DEPLOYMENT_TARGET':'18.0','SWIFT_VERSION':'5.0','CODE_SIGNING_ALLOWED':'NO','GENERATE_INFOPLIST_FILE':'YES','TARGETED_DEVICE_FAMILY':'1','SUPPORTED_PLATFORMS':'iphonesimulator'}
pconfig=obj(11,isa='XCBuildConfiguration',name='Debug',buildSettings=settings)
hconfig=obj(12,isa='XCBuildConfiguration',name='Debug',buildSettings={'PRODUCT_BUNDLE_IDENTIFIER':'org.example.ci-audio-host','PRODUCT_NAME':'$(TARGET_NAME)','INFOPLIST_KEY_UILaunchScreen_Generation':'YES'})
uconfig=obj(13,isa='XCBuildConfiguration',name='Debug',buildSettings={'PRODUCT_BUNDLE_IDENTIFIER':'org.example.ci-audio-probe-uitests','PRODUCT_NAME':'$(TARGET_NAME)','TEST_TARGET_NAME':'CIHost'})
pl=obj(14,isa='XCConfigurationList',buildConfigurations=[pconfig],defaultConfigurationIsVisible=0,defaultConfigurationName='Debug')
hl=obj(15,isa='XCConfigurationList',buildConfigurations=[hconfig],defaultConfigurationIsVisible=0,defaultConfigurationName='Debug')
ul=obj(16,isa='XCConfigurationList',buildConfigurations=[uconfig],defaultConfigurationIsVisible=0,defaultConfigurationName='Debug')
host_id=f'{17:024X}';ui_id=f'{18:024X}';root_id=f'{19:024X}'
proxy=obj(20,isa='PBXContainerItemProxy',containerPortal=root_id,proxyType=1,remoteGlobalIDString=host_id,remoteInfo='CIHost')
dependency=obj(21,isa='PBXTargetDependency',target=host_id,targetProxy=proxy)
obj(17,isa='PBXNativeTarget',name='CIHost',productName='CIHost',productType='com.apple.product-type.application',productReference=host_product,buildConfigurationList=hl,buildPhases=[host_phase],buildRules=[],dependencies=[])
obj(18,isa='PBXNativeTarget',name='CIProbeUITests',productName='CIProbeUITests',productType='com.apple.product-type.bundle.ui-testing',productReference=ui_product,buildConfigurationList=ul,buildPhases=[ui_phase],buildRules=[],dependencies=[dependency])
obj(19,isa='PBXProject',attributes={'LastUpgradeCheck':'1640','TargetAttributes':{ui_id:{'TestTargetID':host_id}}},buildConfigurationList=pl,compatibilityVersion='Xcode 14.0',developmentRegion='en',knownRegions=['en','Base'],mainGroup=main,productRefGroup=products,projectDirPath='',projectRoot='',targets=[host_id,ui_id])
def render(value):
    if isinstance(value,dict):return '{\n'+''.join(json.dumps(str(k))+' = '+render(v)+';\n' for k,v in value.items())+'}'
    if isinstance(value,list):return '(\n'+''.join(render(v)+',\n' for v in value)+')'
    if isinstance(value,int):return str(value)
    return json.dumps(value)
(project/'project.pbxproj').write_text('// !$*UTF8*$!\n'+render({'archiveVersion':1,'classes':{},'objectVersion':56,'objects':objects,'rootObject':root_id})+'\n')
schemes=project/'xcshareddata/xcschemes';schemes.mkdir(parents=True,exist_ok=True)
def reference(identifier,name):return f'<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{identifier}" BuildableName="{name}" BlueprintName="{name.split(".")[0]}" ReferencedContainer="container:CIProbeV15.xcodeproj"/>'
(schemes/'CIProbeV15.xcscheme').write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1640" version="1.3"><BuildAction parallelizeBuildables="NO" buildImplicitDependencies="YES"><BuildActionEntries>
<BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="NO" buildForArchiving="NO" buildForAnalyzing="YES">{reference(host_id,'CIHost.app')}</BuildActionEntry>
<BuildActionEntry buildForTesting="YES" buildForRunning="NO" buildForProfiling="NO" buildForArchiving="NO" buildForAnalyzing="YES">{reference(ui_id,'CIProbeUITests.xctest')}</BuildActionEntry>
</BuildActionEntries></BuildAction><TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES"><Testables><TestableReference skipped="NO">{reference(ui_id,'CIProbeUITests.xctest')}</TestableReference></Testables></TestAction></Scheme>
''')
print(project)
