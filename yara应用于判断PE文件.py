#利用yara判断PE文件。
import yara,os
def IsMatch(rule,target_path):
  m=rule.match(target_path)
  if m:
    return True
  else:
    return False

def CompileRules(rule_path):
  ruleSet=[]
  for root,sub,files in  os.walk(rule_path):
    for file in files:
      print("\t"+os.path.join(root,file))
      try:
        rule=yara.compile(os.path.join(root,file))
        ruleSet.append(rule)
      except Exception as e:
        print("Error"+str(e))
  print('\n')
  return ruleSet

def scanTargetDirectory(target_path,ruleSet):
  for root, sub, files in os.walk(target_path):
    for file in files:
      print("\t"+os.path.join(root,file))
      for rule in ruleSet:
        if(IsMatch(rule,os.path.join(root,file))):
          matches = rule.match(os.path.join(root,file))
          if(matches):
            print("\t\tYARA MATCH:"+os.path.join(root,file)+"\t"+matches[0].rule)

if __name__=="__main__":
  rule_path=input("please input rule_path:")
  target_path=input("please input target_path:")
  ruleSet=CompileRules(rule_path)
  scanTargetDirectory(target_path, ruleSet)
